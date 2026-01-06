"""OSINT tasks with job tracking and evidence storage."""
import os
import json
import socket
from datetime import datetime
from typing import Any

import dns.resolver
import httpx
import structlog
from celery import Task
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from worker_app.celery_app import celery_app

logger = structlog.get_logger(__name__)

# Database connection for updating job status
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://osint:osint@postgres:5432/osint")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# MinIO settings
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minio123456")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "evidence")


def store_evidence(job_id: str, workspace_id: str, job_type: str, data: dict) -> str:
    """Store raw evidence in MinIO."""
    from minio import Minio
    from io import BytesIO
    
    endpoint = MINIO_ENDPOINT
    if endpoint.startswith("http://"):
        endpoint = endpoint[7:]
    
    client = Minio(endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, secure=False)
    
    # Ensure bucket exists
    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)
    
    # Generate path
    date_str = datetime.utcnow().strftime("%Y/%m/%d")
    object_name = f"{workspace_id}/{job_type}/{date_str}/{job_id}.json"
    
    # Store
    data_bytes = json.dumps(data, indent=2, default=str).encode("utf-8")
    client.put_object(MINIO_BUCKET, object_name, BytesIO(data_bytes), len(data_bytes))
    
    return f"s3://{MINIO_BUCKET}/{object_name}"


def update_job_status(job_id: str, status: str, result: dict = None, error: str = None, evidence_path: str = None):
    """Update job status in database."""
    with SessionLocal() as db:
        updates = [f"status = '{status}'"]
        
        if status == "RUNNING":
            updates.append("started_at = NOW()")
        elif status in ("COMPLETED", "FAILED"):
            updates.append("completed_at = NOW()")
        
        if result:
            result_json = json.dumps(result).replace("'", "''")
            updates.append(f"result = '{result_json}'::jsonb")
        
        if error:
            updates.append(f"error_message = '{error}'")
        
        if evidence_path:
            updates.append(f"raw_evidence_path = '{evidence_path}'")
        
        query = f"UPDATE jobs SET {', '.join(updates)} WHERE id = '{job_id}'"
        db.execute(text(query))
        db.commit()


class OSINTTask(Task):
    """Base task with automatic job status updates and retry with backoff."""
    
    autoretry_for = (Exception,)
    retry_backoff = True
    retry_backoff_max = 600  # Max 10 minutes
    retry_jitter = True
    max_retries = 3
    
    def before_start(self, task_id, args, kwargs):
        """Called before task starts."""
        job_id = kwargs.get("job_id")
        if job_id:
            update_job_status(job_id, "RUNNING")
            logger.info("Job started", job_id=job_id, task_id=task_id)
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called on success."""
        job_id = kwargs.get("job_id")
        if job_id:
            logger.info("Job completed", job_id=job_id, task_id=task_id)
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called on failure."""
        job_id = kwargs.get("job_id")
        if job_id:
            update_job_status(job_id, "FAILED", error=str(exc))
            logger.error("Job failed", job_id=job_id, task_id=task_id, error=str(exc))


# =============================================================================
# DNS Lookup Task
# =============================================================================

@celery_app.task(bind=True, base=OSINTTask, name="worker_app.tasks.dns_lookup")
def dns_lookup(
    self,
    job_id: str,
    workspace_id: str,
    target_id: str,
    config: dict,
) -> dict:
    """Perform DNS lookup for a domain."""
    domain = config.get("domain")
    record_types = config.get("record_types", ["A", "AAAA", "MX", "NS", "TXT"])
    
    logger.info("DNS lookup", job_id=job_id, domain=domain)
    
    results = {
        "domain": domain,
        "records": {},
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            results["records"][record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            results["records"][record_type] = []
        except dns.resolver.NXDOMAIN:
            results["error"] = f"Domain {domain} does not exist"
            break
        except Exception as e:
            results["records"][record_type] = {"error": str(e)}
    
    # Store raw evidence
    evidence_path = store_evidence(job_id, workspace_id, "dns_lookup", results)
    
    # Normalize result
    normalized = {
        "domain": domain,
        "record_count": sum(len(v) if isinstance(v, list) else 0 for v in results["records"].values()),
        "has_mx": len(results["records"].get("MX", [])) > 0,
        "nameservers": results["records"].get("NS", []),
    }
    
    update_job_status(job_id, "COMPLETED", result=normalized, evidence_path=evidence_path)
    return normalized


# =============================================================================
# WHOIS Lookup Task
# =============================================================================

@celery_app.task(bind=True, base=OSINTTask, name="worker_app.tasks.whois_lookup")
def whois_lookup(
    self,
    job_id: str,
    workspace_id: str,
    target_id: str,
    config: dict,
) -> dict:
    """Perform WHOIS lookup for a domain."""
    import subprocess
    
    domain = config.get("domain")
    logger.info("WHOIS lookup", job_id=job_id, domain=domain)
    
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        raw_result = {
            "domain": domain,
            "raw": result.stdout,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Store raw evidence
        evidence_path = store_evidence(job_id, workspace_id, "whois_lookup", raw_result)
        
        # Parse common fields
        lines = result.stdout.split("\n")
        parsed = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key and value and key not in parsed:
                    parsed[key] = value
        
        normalized = {
            "domain": domain,
            "registrar": parsed.get("registrar"),
            "creation_date": parsed.get("creation_date") or parsed.get("created"),
            "expiration_date": parsed.get("expiration_date") or parsed.get("registry_expiry_date"),
            "name_servers": [v for k, v in parsed.items() if "name_server" in k][:4],
        }
        
        update_job_status(job_id, "COMPLETED", result=normalized, evidence_path=evidence_path)
        return normalized
        
    except subprocess.TimeoutExpired:
        raise Exception("WHOIS lookup timed out")


# =============================================================================
# Email Verify Task
# =============================================================================

@celery_app.task(bind=True, base=OSINTTask, name="worker_app.tasks.email_verify")
def email_verify(
    self,
    job_id: str,
    workspace_id: str,
    target_id: str,
    config: dict,
) -> dict:
    """Verify email address exists."""
    email = config.get("email")
    logger.info("Email verify", job_id=job_id, email=email)
    
    results = {
        "email": email,
        "valid_format": "@" in email and "." in email.split("@")[1] if "@" in email else False,
        "domain_exists": False,
        "mx_records": [],
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    if results["valid_format"]:
        domain = email.split("@")[1]
        resolver = dns.resolver.Resolver()
        try:
            mx_records = resolver.resolve(domain, "MX")
            results["domain_exists"] = True
            results["mx_records"] = [
                {"priority": r.preference, "host": str(r.exchange)}
                for r in mx_records
            ]
        except dns.resolver.NXDOMAIN:
            results["domain_exists"] = False
        except Exception as e:
            results["mx_error"] = str(e)
    
    # Store evidence
    evidence_path = store_evidence(job_id, workspace_id, "email_verify", results)
    
    normalized = {
        "email": email,
        "valid": results["valid_format"] and results["domain_exists"],
        "has_mx": len(results["mx_records"]) > 0,
    }
    
    update_job_status(job_id, "COMPLETED", result=normalized, evidence_path=evidence_path)
    return normalized


# =============================================================================
# Port Scan Task
# =============================================================================

@celery_app.task(bind=True, base=OSINTTask, name="worker_app.tasks.port_scan")
def port_scan(
    self,
    job_id: str,
    workspace_id: str,
    target_id: str,
    config: dict,
) -> dict:
    """Perform basic port scan."""
    target = config.get("target")
    ports = config.get("ports", [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080])
    
    logger.info("Port scan", job_id=job_id, target=target)
    
    results = {
        "target": target,
        "open_ports": [],
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((target, port)) == 0:
                results["open_ports"].append({
                    "port": port,
                    "state": "open",
                })
            sock.close()
        except Exception:
            pass
    
    # Store evidence
    evidence_path = store_evidence(job_id, workspace_id, "port_scan", results)
    
    normalized = {
        "target": target,
        "open_ports": [p["port"] for p in results["open_ports"]],
        "total_open": len(results["open_ports"]),
    }
    
    update_job_status(job_id, "COMPLETED", result=normalized, evidence_path=evidence_path)
    return normalized


# =============================================================================
# Noop Task (for testing)
# =============================================================================

@celery_app.task(name="noop")
def noop(job_id: str = None, **kwargs):
    """No-op task for testing."""
    return {"job_id": job_id, "status": "ok"}
