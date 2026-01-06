"""
OSINT Worker Tasks - Unified Job Execution

Contract:
- Worker receives ONLY job_id
- Always rehydrate job from DB (source of truth)
- Always store raw_evidence BEFORE processing findings
- NEVER delete evidence (audit trail)
- NEVER receive target directly
"""
import os
import json
import socket
import hashlib
from datetime import datetime
from uuid import UUID
from typing import Optional, Any

import dns.resolver
import structlog
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from minio import Minio
from io import BytesIO
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from worker_app.celery_app import celery_app

logger = structlog.get_logger(__name__)

# =============================================================================
# Database Configuration
# =============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://osint:osint@postgres:5432/osint")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

# =============================================================================
# MinIO Configuration
# =============================================================================

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minio123456")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "evidence")


def get_minio_client() -> Minio:
    """Get MinIO client."""
    endpoint = MINIO_ENDPOINT
    if endpoint.startswith("http://"):
        endpoint = endpoint[7:]
    return Minio(endpoint, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, secure=False)


# =============================================================================
# Job Hydration (from DB)
# =============================================================================

def rehydrate_job(job_id: str) -> dict:
    """
    Rehydrate job from database.
    
    Returns dict with: id, workspace_id, target_id, technique_code, params_json, 
                       target_type, target_value, attempt, max_attempts
    """
    with SessionLocal() as db:
        result = db.execute(
            text("""
                SELECT 
                    j.id, j.workspace_id, j.target_id, j.technique_code, 
                    j.params_json, j.attempt, j.max_attempts,
                    t.target_type, t.value as target_value
                FROM jobs j
                JOIN targets t ON j.target_id = t.id
                WHERE j.id = :job_id
            """),
            {"job_id": job_id}
        ).fetchone()
        
        if not result:
            raise ValueError(f"Job {job_id} not found")
        
        return {
            "id": str(result[0]),
            "workspace_id": str(result[1]),
            "target_id": str(result[2]),
            "technique_code": result[3],
            "params_json": result[4] or {},
            "attempt": result[5],
            "max_attempts": result[6],
            "target_type": result[7],
            "target_value": result[8],
        }


# =============================================================================
# Job Status Updates
# =============================================================================

def update_job_running(job_id: str):
    """Mark job as RUNNING."""
    with SessionLocal() as db:
        db.execute(
            text("""
                UPDATE jobs 
                SET status = 'RUNNING', 
                    started_at = NOW(),
                    attempt = attempt + 1
                WHERE id = :job_id
            """),
            {"job_id": job_id}
        )
        db.commit()


def update_job_succeeded(job_id: str):
    """Mark job as SUCCEEDED."""
    with SessionLocal() as db:
        db.execute(
            text("""
                UPDATE jobs 
                SET status = 'SUCCEEDED', 
                    finished_at = NOW()
                WHERE id = :job_id
            """),
            {"job_id": job_id}
        )
        db.commit()


def update_job_retrying(job_id: str, error_code: str, error_message: str):
    """Mark job as RETRYING."""
    with SessionLocal() as db:
        db.execute(
            text("""
                UPDATE jobs 
                SET status = 'RETRYING', 
                    error_code = :error_code,
                    error_message = :error_message
                WHERE id = :job_id
            """),
            {"job_id": job_id, "error_code": error_code, "error_message": error_message[:1000]}
        )
        db.commit()


def update_job_failed(job_id: str, error_code: str, error_message: str):
    """Mark job as FAILED."""
    with SessionLocal() as db:
        db.execute(
            text("""
                UPDATE jobs 
                SET status = 'FAILED', 
                    finished_at = NOW(),
                    error_code = :error_code,
                    error_message = :error_message
                WHERE id = :job_id
            """),
            {"job_id": job_id, "error_code": error_code, "error_message": error_message[:1000]}
        )
        db.commit()


def update_job_dead_letter(job_id: str, error_code: str, error_message: str):
    """Mark job as DEAD_LETTER (exhausted retries)."""
    with SessionLocal() as db:
        db.execute(
            text("""
                UPDATE jobs 
                SET status = 'DEAD_LETTER', 
                    finished_at = NOW(),
                    error_code = :error_code,
                    error_message = :error_message
                WHERE id = :job_id
            """),
            {"job_id": job_id, "error_code": error_code, "error_message": f"Exhausted retries: {error_message}"[:1000]}
        )
        db.commit()


# =============================================================================
# Raw Evidence Storage (MinIO + DB)
# =============================================================================

def calculate_sha256(content: bytes) -> str:
    """Calculate SHA256 hash."""
    return hashlib.sha256(content).hexdigest()


def store_raw_evidence(
    workspace_id: str,
    job_id: str,
    source: str,
    data: dict,
    retrieval_meta: dict = None,
) -> str:
    """
    Store raw evidence in MinIO and create DB record.
    
    Returns storage_uri.
    """
    # Serialize data
    captured_at = datetime.utcnow()
    content = json.dumps(data, indent=2, default=str).encode("utf-8")
    sha256_hash = calculate_sha256(content)
    
    # Generate storage path: {workspace_id}/{job_id}/{source}_{timestamp}_{sha256[:8]}.json
    ts_str = captured_at.strftime("%Y%m%d_%H%M%S")
    object_name = f"{workspace_id}/{job_id}/{source}_{ts_str}_{sha256_hash[:8]}.json"
    storage_uri = f"s3://{MINIO_BUCKET}/{object_name}"
    
    # Upload to MinIO
    client = get_minio_client()
    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)
    
    client.put_object(
        MINIO_BUCKET, 
        object_name, 
        BytesIO(content), 
        len(content),
        content_type="application/json"
    )
    
    # Create DB record
    with SessionLocal() as db:
        db.execute(
            text("""
                INSERT INTO raw_evidence 
                (id, workspace_id, job_id, storage_uri, content_type, sha256, size_bytes, 
                 source, retrieval_meta_json, captured_at, created_at)
                VALUES 
                (gen_random_uuid(), :workspace_id, :job_id, :storage_uri, 'application/json', 
                 :sha256, :size_bytes, :source, :retrieval_meta, :captured_at, NOW())
            """),
            {
                "workspace_id": workspace_id,
                "job_id": job_id,
                "storage_uri": storage_uri,
                "sha256": sha256_hash,
                "size_bytes": len(content),
                "source": source,
                "retrieval_meta": json.dumps(retrieval_meta or {}),
                "captured_at": captured_at,
            }
        )
        db.commit()
    
    logger.info("Stored raw evidence", storage_uri=storage_uri, size=len(content))
    return storage_uri


# =============================================================================
# Findings Storage (with deduplication)
# =============================================================================

def generate_finding_fingerprint(workspace_id: str, finding_type: str, subject: str, data: dict) -> str:
    """Generate fingerprint for deduplication."""
    stable_data = {k: v for k, v in data.items() if k not in ("timestamp", "ttl", "cached_at")}
    data_str = json.dumps(stable_data, sort_keys=True, separators=(',', ':'), default=str)
    composite = f"{workspace_id}{finding_type}{subject}{data_str}"
    return hashlib.sha256(composite.encode()).hexdigest()


def upsert_finding(
    workspace_id: str,
    target_id: str,
    job_id: str,
    finding_type: str,
    subject: str,
    confidence: int,
    data: dict,
) -> str:
    """
    Upsert finding (insert or update last_seen_at).
    
    Returns finding_id.
    """
    fingerprint = generate_finding_fingerprint(workspace_id, finding_type, subject, data)
    
    with SessionLocal() as db:
        # Try to get existing
        existing = db.execute(
            text("""
                SELECT id FROM findings 
                WHERE workspace_id = :workspace_id AND finding_fingerprint = :fingerprint
            """),
            {"workspace_id": workspace_id, "fingerprint": fingerprint}
        ).fetchone()
        
        if existing:
            # Update last_seen_at
            db.execute(
                text("""
                    UPDATE findings 
                    SET last_seen_at = NOW(), job_id = :job_id
                    WHERE id = :id
                """),
                {"id": existing[0], "job_id": job_id}
            )
            db.commit()
            return str(existing[0])
        else:
            # Insert new
            result = db.execute(
                text("""
                    INSERT INTO findings 
                    (id, workspace_id, target_id, job_id, finding_type, subject, 
                     confidence, data_json, finding_fingerprint, first_seen_at, last_seen_at, created_at)
                    VALUES 
                    (gen_random_uuid(), :workspace_id, :target_id, :job_id, :finding_type, 
                     :subject, :confidence, :data_json, :fingerprint, NOW(), NOW(), NOW())
                    RETURNING id
                """),
                {
                    "workspace_id": workspace_id,
                    "target_id": target_id,
                    "job_id": job_id,
                    "finding_type": finding_type,
                    "subject": subject,
                    "confidence": confidence,
                    "data_json": json.dumps(data),
                    "fingerprint": fingerprint,
                }
            )
            finding_id = result.fetchone()[0]
            db.commit()
            return str(finding_id)


# =============================================================================
# Technique Implementations
# =============================================================================

def execute_dns_lookup(job: dict) -> list[dict]:
    """Execute DNS lookup technique."""
    domain = job["target_value"]
    params = job["params_json"]
    record_types = params.get("record_types", ["A", "AAAA", "MX", "NS", "TXT"])
    
    logger.info("DNS lookup", job_id=job["id"], domain=domain)
    
    raw_data = {
        "domain": domain,
        "records": {},
        "timestamp": datetime.utcnow().isoformat(),
        "source": "dnspython",
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            raw_data["records"][record_type] = [
                {"value": str(rdata), "ttl": answers.rrset.ttl}
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            raw_data["records"][record_type] = []
        except dns.resolver.NXDOMAIN:
            raw_data["error"] = f"Domain {domain} does not exist"
            raw_data["records"][record_type] = []
            break
        except Exception as e:
            raw_data["records"][record_type] = [{"error": str(e)}]
    
    # Store raw evidence FIRST
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="dns_resolver",
        data=raw_data,
        retrieval_meta={"resolver": str(resolver.nameservers), "record_types": record_types},
    )
    
    # Create findings
    findings = []
    for record_type, records in raw_data["records"].items():
        for record in records:
            if isinstance(record, dict) and "value" in record:
                finding = {
                    "finding_type": "DOMAIN_DNS_RECORD",
                    "subject": domain,
                    "confidence": 95,
                    "data": {
                        "record_type": record_type,
                        "value": record["value"],
                        "ttl": record.get("ttl"),
                    },
                }
                findings.append(finding)
                upsert_finding(
                    workspace_id=job["workspace_id"],
                    target_id=job["target_id"],
                    job_id=job["id"],
                    **finding,
                )
    
    return findings


def execute_whois_lookup(job: dict) -> list[dict]:
    """Execute WHOIS lookup technique."""
    import subprocess
    
    domain = job["target_value"]
    logger.info("WHOIS lookup", job_id=job["id"], domain=domain)
    
    result = subprocess.run(
        ["whois", domain],
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    raw_data = {
        "domain": domain,
        "raw_output": result.stdout,
        "timestamp": datetime.utcnow().isoformat(),
        "source": "whois_cli",
        "exit_code": result.returncode,
    }
    
    # Store raw evidence FIRST
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="whois_cli",
        data=raw_data,
        retrieval_meta={"command": "whois", "domain": domain},
    )
    
    # Parse WHOIS output
    lines = result.stdout.split("\n")
    parsed = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key and value and key not in parsed:
                parsed[key] = value
    
    # Create findings
    findings = []
    
    # Registrar finding
    if parsed.get("registrar"):
        finding = {
            "finding_type": "DOMAIN_REGISTRAR",
            "subject": domain,
            "confidence": 90,
            "data": {"registrar": parsed["registrar"]},
        }
        findings.append(finding)
        upsert_finding(
            workspace_id=job["workspace_id"],
            target_id=job["target_id"],
            job_id=job["id"],
            **finding,
        )
    
    # Registration dates finding
    creation = parsed.get("creation_date") or parsed.get("created")
    expiry = parsed.get("registry_expiry_date") or parsed.get("expiration_date")
    if creation or expiry:
        finding = {
            "finding_type": "DOMAIN_REGISTRATION",
            "subject": domain,
            "confidence": 90,
            "data": {
                "creation_date": creation,
                "expiration_date": expiry,
                "updated_date": parsed.get("updated_date") or parsed.get("last_updated"),
            },
        }
        findings.append(finding)
        upsert_finding(
            workspace_id=job["workspace_id"],
            target_id=job["target_id"],
            job_id=job["id"],
            **finding,
        )
    
    return findings


def execute_email_verify(job: dict) -> list[dict]:
    """Execute email verification technique."""
    email = job["target_value"]
    logger.info("Email verify", job_id=job["id"], email=email)
    
    raw_data = {
        "email": email,
        "valid_format": "@" in email and "." in email.split("@")[-1],
        "domain_check": {},
        "mx_records": [],
        "timestamp": datetime.utcnow().isoformat(),
        "source": "dns_mx_check",
    }
    
    if raw_data["valid_format"]:
        domain = email.split("@")[1]
        raw_data["domain_check"]["domain"] = domain
        
        resolver = dns.resolver.Resolver()
        try:
            mx_records = resolver.resolve(domain, "MX")
            raw_data["domain_check"]["exists"] = True
            raw_data["mx_records"] = [
                {"priority": r.preference, "host": str(r.exchange)}
                for r in mx_records
            ]
        except dns.resolver.NXDOMAIN:
            raw_data["domain_check"]["exists"] = False
        except Exception as e:
            raw_data["domain_check"]["error"] = str(e)
    
    # Store raw evidence FIRST
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="email_mx_check",
        data=raw_data,
        retrieval_meta={"email": email},
    )
    
    # Create findings
    findings = []
    
    # Email valid finding
    is_deliverable = (
        raw_data["valid_format"] 
        and raw_data["domain_check"].get("exists", False) 
        and len(raw_data["mx_records"]) > 0
    )
    
    finding = {
        "finding_type": "EMAIL_DELIVERABLE",
        "subject": email,
        "confidence": 80 if is_deliverable else 70,
        "data": {
            "valid_format": raw_data["valid_format"],
            "domain_exists": raw_data["domain_check"].get("exists", False),
            "has_mx": len(raw_data["mx_records"]) > 0,
            "deliverable": is_deliverable,
        },
    }
    findings.append(finding)
    upsert_finding(
        workspace_id=job["workspace_id"],
        target_id=job["target_id"],
        job_id=job["id"],
        **finding,
    )
    
    # Email provider finding (from MX)
    if raw_data["mx_records"]:
        mx_host = raw_data["mx_records"][0]["host"].lower()
        provider = None
        if "google" in mx_host or "gmail" in mx_host:
            provider = "Google Workspace"
        elif "outlook" in mx_host or "microsoft" in mx_host:
            provider = "Microsoft 365"
        elif "protonmail" in mx_host:
            provider = "ProtonMail"
        
        if provider:
            finding = {
                "finding_type": "EMAIL_PROVIDER",
                "subject": email,
                "confidence": 85,
                "data": {"provider": provider, "mx_host": mx_host},
            }
            findings.append(finding)
            upsert_finding(
                workspace_id=job["workspace_id"],
                target_id=job["target_id"],
                job_id=job["id"],
                **finding,
            )
    
    return findings


def execute_port_scan(job: dict) -> list[dict]:
    """Execute port scan technique."""
    target = job["target_value"]
    params = job["params_json"]
    ports = params.get("ports", [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080])
    
    logger.info("Port scan", job_id=job["id"], target=target, ports_count=len(ports))
    
    raw_data = {
        "target": target,
        "ports_scanned": ports,
        "results": [],
        "timestamp": datetime.utcnow().isoformat(),
        "source": "socket_connect",
    }
    
    for port in ports:
        port_result = {"port": port, "state": "closed"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                port_result["state"] = "open"
            sock.close()
        except Exception as e:
            port_result["error"] = str(e)
        
        raw_data["results"].append(port_result)
    
    # Store raw evidence FIRST
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="port_scanner",
        data=raw_data,
        retrieval_meta={"target": target, "ports": ports},
    )
    
    # Create findings for open ports
    findings = []
    for result in raw_data["results"]:
        if result["state"] == "open":
            finding = {
                "finding_type": "PORT_OPEN",
                "subject": target,
                "confidence": 95,
                "data": {
                    "port": result["port"],
                    "state": "open",
                    "protocol": "tcp",
                },
            }
            findings.append(finding)
            upsert_finding(
                workspace_id=job["workspace_id"],
                target_id=job["target_id"],
                job_id=job["id"],
                **finding,
            )
    
    return findings


# =============================================================================
# Technique Router
# =============================================================================

TECHNIQUE_HANDLERS = {
    "dns_lookup": execute_dns_lookup,
    "whois_lookup": execute_whois_lookup,
    "email_verify": execute_email_verify,
    "port_scan": execute_port_scan,
}


# =============================================================================
# Unified Task Executor
# =============================================================================

class OSINTTask(Task):
    """
    Base task with retry and timeout handling.
    """
    autoretry_for = (Exception,)
    retry_backoff = True
    retry_backoff_max = 600  # Max 10 min between retries
    retry_jitter = True
    max_retries = 3
    soft_time_limit = 300  # 5 min soft limit
    time_limit = 360  # 6 min hard limit


@celery_app.task(bind=True, base=OSINTTask, name="worker_app.tasks.execute_job")
def execute_job(self, job_id: str) -> dict:
    """
    Unified job executor.
    
    Contract:
    1. Receive ONLY job_id
    2. Rehydrate job from DB (source of truth)
    3. Update status to RUNNING
    4. Execute technique
    5. Store raw_evidence FIRST
    6. Create/upsert findings
    7. Update status to SUCCEEDED or handle failure
    """
    logger.info("Job executor started", job_id=job_id, task_id=self.request.id)
    
    try:
        # 1. Rehydrate job from DB
        job = rehydrate_job(job_id)
        logger.info(
            "Job rehydrated",
            job_id=job_id,
            technique=job["technique_code"],
            target=job["target_value"],
            attempt=job["attempt"],
        )
        
        # 2. Update status to RUNNING
        update_job_running(job_id)
        
        # 3. Get technique handler
        handler = TECHNIQUE_HANDLERS.get(job["technique_code"])
        if not handler:
            raise ValueError(f"Unknown technique: {job['technique_code']}")
        
        # 4. Execute technique (stores evidence + findings internally)
        findings = handler(job)
        
        # 5. Mark as SUCCEEDED
        update_job_succeeded(job_id)
        
        logger.info(
            "Job completed",
            job_id=job_id,
            technique=job["technique_code"],
            findings_count=len(findings),
        )
        
        return {
            "job_id": job_id,
            "status": "SUCCEEDED",
            "findings_count": len(findings),
        }
        
    except SoftTimeLimitExceeded:
        # Timeout - check if can retry
        try:
            job = rehydrate_job(job_id)
            if job["attempt"] < job["max_attempts"]:
                update_job_retrying(job_id, "TIMEOUT", "Task exceeded time limit")
                raise  # Re-raise to trigger Celery retry
            else:
                update_job_dead_letter(job_id, "TIMEOUT", "Task exceeded time limit")
        except Exception:
            update_job_failed(job_id, "TIMEOUT", "Task exceeded time limit")
        
        return {"job_id": job_id, "status": "FAILED", "error": "timeout"}
        
    except Exception as e:
        error_code = type(e).__name__
        error_message = str(e)
        
        logger.error("Job failed", job_id=job_id, error=error_message)
        
        # Check if can retry
        try:
            job = rehydrate_job(job_id)
            if job["attempt"] < job["max_attempts"]:
                update_job_retrying(job_id, error_code, error_message)
                raise  # Re-raise to trigger Celery retry
            else:
                update_job_dead_letter(job_id, error_code, error_message)
        except ValueError:
            # Job not found, just fail
            pass
        except Exception:
            update_job_failed(job_id, error_code, error_message)
        
        return {"job_id": job_id, "status": "FAILED", "error": error_message}


# =============================================================================
# Health Check Task
# =============================================================================

@celery_app.task(name="worker_app.tasks.health_check")
def health_check() -> dict:
    """Health check task."""
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "hostname": os.getenv("HOSTNAME", "unknown"),
    }
