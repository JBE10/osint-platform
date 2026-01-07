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
import re
import json
import socket
import hashlib
import time
import threading
from datetime import datetime
from uuid import UUID
from typing import Optional, Any
from collections import defaultdict

import dns.resolver
import dns.rdatatype
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
# Outbound Rate Limiting (per technique + per domain via Redis)
# =============================================================================

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL)


class OutboundRateLimiter:
    """
    Token bucket rate limiter for outbound requests.
    Prevents abuse of external services.
    """
    _limiters = {}
    _lock = threading.Lock()
    
    # Technique-specific limits: (requests_per_minute, burst)
    LIMITS = {
        # Domain techniques
        "domain_dns_lookup": (30, 5),       # 30/min, burst 5
        "domain_whois_rdap_lookup": (10, 2), # 10/min, burst 2 (WHOIS is expensive)
        "dns_lookup": (30, 5),
        "whois_lookup": (10, 2),
        
        # Username techniques (external API limits)
        "username_github_lookup": (1, 1),   # 60/hour = 1/min (without token)
        "username_reddit_lookup": (20, 2),  # ~1 req per 3s = 20/min, burst 2
        
        # Other techniques
        "email_verify": (20, 3),
        "port_scan": (5, 1),                 # Very limited
        "default": (20, 3),
    }
    
    def __init__(self, technique: str):
        rpm, burst = self.LIMITS.get(technique, self.LIMITS["default"])
        self.rate = rpm / 60.0  # tokens per second
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    @classmethod
    def get(cls, technique: str) -> "OutboundRateLimiter":
        with cls._lock:
            if technique not in cls._limiters:
                cls._limiters[technique] = cls(technique)
            return cls._limiters[technique]
    
    def acquire(self, timeout: float = 30.0) -> bool:
        """Try to acquire a token, waiting up to timeout seconds."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
            
            time.sleep(0.1)
        return False


# Per-domain/username throttle configuration (cooldown in seconds)
DOMAIN_THROTTLE = {
    # Domain techniques
    "domain_dns_lookup": 2,           # 2s between same domain DNS lookups
    "domain_whois_rdap_lookup": 60,   # 60s between same domain RDAP lookups (avoid hammering)
    
    # Username techniques (avoid hammering same username)
    "username_github_lookup": 300,    # 5 min between same username lookups
    "username_reddit_lookup": 180,    # 3 min between same username lookups
    
    "default": 5,
}


def check_domain_throttle(technique: str, domain: str) -> bool:
    """
    Check if domain is throttled (Redis-based).
    Returns True if OK to proceed, False if throttled.
    """
    cooldown = DOMAIN_THROTTLE.get(technique, DOMAIN_THROTTLE["default"])
    key = f"osint:throttle:{technique}:{domain}"
    
    try:
        # Check if key exists
        if redis_client.exists(key):
            ttl = redis_client.ttl(key)
            logger.debug("Domain throttled", domain=domain, technique=technique, ttl=ttl)
            return False
        
        # Set key with TTL
        redis_client.setex(key, cooldown, "1")
        return True
    except Exception as e:
        logger.warning("Redis throttle check failed", error=str(e))
        return True  # Allow on Redis failure


def wait_for_domain_throttle(technique: str, domain: str, max_wait: float = 120.0) -> bool:
    """
    Wait for domain throttle to clear.
    Returns True if cleared, False if timeout.
    """
    cooldown = DOMAIN_THROTTLE.get(technique, DOMAIN_THROTTLE["default"])
    key = f"osint:throttle:{technique}:{domain}"
    
    deadline = time.time() + max_wait
    
    while time.time() < deadline:
        try:
            if not redis_client.exists(key):
                # Set new throttle and proceed
                redis_client.setex(key, cooldown, "1")
                return True
            
            ttl = redis_client.ttl(key)
            if ttl <= 0:
                redis_client.setex(key, cooldown, "1")
                return True
            
            # Wait for throttle to clear
            wait_time = min(ttl, 1.0)
            time.sleep(wait_time)
            
        except Exception as e:
            logger.warning("Redis throttle wait failed", error=str(e))
            return True
    
    return False


def rate_limited_request(technique: str, domain: str = None, timeout: float = 30.0):
    """
    Rate limit check for outbound requests.
    
    Two-level limiting:
    1. Per-technique (token bucket) - global rate
    2. Per-domain (Redis TTL) - prevents hammering same target
    """
    # Level 1: Technique rate limit
    limiter = OutboundRateLimiter.get(technique)
    if not limiter.acquire(timeout):
        raise Exception(f"Rate limit exceeded for technique {technique}")
    
    # Level 2: Domain-level throttle (if domain provided)
    if domain:
        if not wait_for_domain_throttle(technique, domain, max_wait=timeout):
            raise Exception(f"Domain throttle timeout for {domain} ({technique})")


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
    
    ALWAYS call this BEFORE normalizing findings.
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
    """
    Generate fingerprint for deduplication.
    
    Formula: sha256(workspace_id + finding_type + subject + canonical_json(data))
    
    Benefits:
    - Avoids duplicates within same workspace
    - Enables last_seen_at updates
    - Correlates findings across jobs
    
    Volatile keys excluded from data: timestamp, ttl, cached_at, query_time_ms
    """
    volatile_keys = ("timestamp", "ttl", "cached_at", "query_time_ms", "last_checked", "queried_at")
    stable_data = {k: v for k, v in data.items() if k not in volatile_keys}
    # Canonical JSON: sorted keys, minimal whitespace
    canonical_json = json.dumps(stable_data, sort_keys=True, separators=(',', ':'), default=str)
    composite = f"{workspace_id}{finding_type}{subject}{canonical_json}"
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
# SPF/DMARC Parsing Utilities
# =============================================================================

def parse_spf_record(txt_value: str) -> dict:
    """Parse SPF record from TXT value."""
    if not txt_value.startswith("v=spf1"):
        return None
    
    result = {
        "version": "spf1",
        "mechanisms": [],
        "modifiers": {},
        "all_policy": None,
    }
    
    parts = txt_value.split()
    for part in parts[1:]:  # Skip v=spf1
        if part.startswith("+") or part.startswith("-") or part.startswith("~") or part.startswith("?"):
            qualifier = part[0]
            mechanism = part[1:]
        else:
            qualifier = "+"
            mechanism = part
        
        if mechanism == "all":
            result["all_policy"] = {"all": True, "qualifier": qualifier}
        elif "=" in mechanism:
            key, value = mechanism.split("=", 1)
            result["modifiers"][key] = value
        else:
            result["mechanisms"].append({"type": mechanism, "qualifier": qualifier})
    
    return result


def parse_dmarc_record(txt_value: str) -> dict:
    """Parse DMARC record from TXT value."""
    if not txt_value.startswith("v=DMARC1"):
        return None
    
    result = {
        "version": "DMARC1",
        "policy": None,
        "subdomain_policy": None,
        "pct": 100,
        "rua": [],
        "ruf": [],
        "adkim": "r",
        "aspf": "r",
    }
    
    parts = txt_value.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key == "p":
                result["policy"] = value
            elif key == "sp":
                result["subdomain_policy"] = value
            elif key == "pct":
                result["pct"] = int(value)
            elif key == "rua":
                result["rua"] = [v.strip() for v in value.split(",")]
            elif key == "ruf":
                result["ruf"] = [v.strip() for v in value.split(",")]
            elif key == "adkim":
                result["adkim"] = value
            elif key == "aspf":
                result["aspf"] = value
    
    return result


# =============================================================================
# TECHNIQUE: DOMAIN_DNS_LOOKUP
# =============================================================================

def execute_domain_dns_lookup(job: dict) -> list[dict]:
    """
    V1 DOMAIN_DNS_LOOKUP - Comprehensive DNS lookup.
    
    Record types: A, AAAA, CNAME, NS, MX, TXT (SPF/DMARC only)
    Resolver: dnspython, configurable (default system)
    
    Security mitigations:
    - Domain validation (no internal TLDs)
    - Private IP detection (DNS rebinding indicator)
    - Rate limiting (30 req/min)
    
    Produces FindingTypes (V1 schema):
    - DOMAIN_IP_ADDRESS     (A/AAAA)
    - DOMAIN_NAMESERVER     (NS)
    - DOMAIN_CNAME          (CNAME)
    - DOMAIN_MAIL_SERVER    (MX)
    - DOMAIN_SPF_POLICY     (parsed from TXT)
    - DOMAIN_DMARC_POLICY   (parsed from TXT)
    """
    from worker_app.security import (
        validate_domain_for_osint,
        validate_resolved_ip,
    )
    
    domain = job["target_value"]
    params = job["params_json"]
    
    # Security: Validate domain first
    validation = validate_domain_for_osint(domain)
    if not validation["valid"]:
        raise ValueError(f"Invalid domain for OSINT: {validation['reason']}")
    if validation["blocked"]:
        raise ValueError(f"Blocked domain: {validation['reason']}")
    
    # Rate limit check (technique + per-domain throttle)
    rate_limited_request("domain_dns_lookup", domain=domain)
    
    logger.info("DOMAIN_DNS_LOOKUP starting", job_id=job["id"], domain=domain)
    
    # Configure resolver (V1: dnspython, configurable)
    resolver = dns.resolver.Resolver()
    resolver.timeout = params.get("timeout", 5)
    resolver.lifetime = params.get("lifetime", 15)
    
    # V1 scope: A, AAAA, CNAME, NS, MX, TXT (for SPF/DMARC)
    record_types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]
    
    # ==========================================================================
    # RAW EVIDENCE (V1 format)
    # ==========================================================================
    raw_data = {
        "domain": domain,
        "records": {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "NS": [],
            "MX": [],
            "TXT": [],
        },
        "resolver": params.get("resolver", "system"),
        "queried_at": datetime.utcnow().isoformat() + "Z",
    }
    
    # Resolve each record type
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type in ("A", "AAAA"):
                    raw_data["records"][record_type].append(str(rdata))
                elif record_type == "CNAME":
                    raw_data["records"][record_type].append(str(rdata))
                elif record_type == "NS":
                    raw_data["records"][record_type].append(str(rdata))
                elif record_type == "MX":
                    raw_data["records"]["MX"].append({
                        "host": str(rdata.exchange).rstrip("."),
                        "priority": rdata.preference,
                    })
                elif record_type == "TXT":
                    txt_value = str(rdata).strip('"')
                    raw_data["records"]["TXT"].append(txt_value)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.warning(f"DNS lookup error for {record_type}", error=str(e))
    
    # Also try DMARC at _dmarc.{domain}
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_value = str(rdata).strip('"')
            if txt_value.startswith("v=DMARC1"):
                raw_data["records"]["TXT"].append(txt_value)
    except Exception:
        pass
    
    # Store raw evidence FIRST (immutable)
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="dnspython",
        data=raw_data,
        retrieval_meta={"resolver": raw_data["resolver"], "timeout": resolver.timeout},
    )
    
    # ==========================================================================
    # NORMALIZE TO FINDINGS (V1 schema)
    # ==========================================================================
    findings = []
    
    # A/AAAA → DOMAIN_IP_ADDRESS
    for ip in raw_data["records"]["A"]:
        ip_check = validate_resolved_ip(ip, domain)
        finding = {
            "finding_type": "DOMAIN_IP_ADDRESS",
            "subject": domain,
            "confidence": 95,
            "data": {
                "ip": ip,
                "version": 4,
                "is_private": ip_check["is_private"],
            },
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    for ip in raw_data["records"]["AAAA"]:
        ip_check = validate_resolved_ip(ip, domain)
        finding = {
            "finding_type": "DOMAIN_IP_ADDRESS",
            "subject": domain,
            "confidence": 95,
            "data": {
                "ip": ip,
                "version": 6,
                "is_private": ip_check["is_private"],
            },
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # CNAME → DOMAIN_CNAME
    for cname in raw_data["records"]["CNAME"]:
        finding = {
            "finding_type": "DOMAIN_CNAME",
            "subject": domain,
            "confidence": 95,
            "data": {"target": cname.rstrip(".")},
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # NS → DOMAIN_NAMESERVER
    for ns in raw_data["records"]["NS"]:
        finding = {
            "finding_type": "DOMAIN_NAMESERVER",
            "subject": domain,
            "confidence": 95,
            "data": {"nameserver": ns.rstrip(".")},
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # MX → DOMAIN_MAIL_SERVER
    for mx in raw_data["records"]["MX"]:
        finding = {
            "finding_type": "DOMAIN_MAIL_SERVER",
            "subject": domain,
            "confidence": 90,
            "data": {
                "host": mx["host"],
                "priority": mx["priority"],
            },
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # TXT → parse SPF / DMARC only (V1 scope)
    for txt_value in raw_data["records"]["TXT"]:
        # SPF
        if txt_value.startswith("v=spf1"):
            spf_parsed = parse_spf_record(txt_value)
            mode = "unknown"
            if spf_parsed and spf_parsed.get("all_policy"):
                q = spf_parsed["all_policy"].get("qualifier", "+")
                mode = {"~": "softfail", "-": "fail", "+": "pass", "?": "neutral"}.get(q, "unknown")
            
            finding = {
                "finding_type": "DOMAIN_SPF_POLICY",
                "subject": domain,
                "confidence": 85,
                "data": {
                    "policy": txt_value,
                    "mode": mode,
                },
            }
            findings.append(finding)
            upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
        
        # DMARC
        elif txt_value.startswith("v=DMARC1"):
            dmarc_parsed = parse_dmarc_record(txt_value)
            rua = []
            if dmarc_parsed:
                rua = [r.replace("mailto:", "") for r in dmarc_parsed.get("rua", [])]
            
            finding = {
                "finding_type": "DOMAIN_DMARC_POLICY",
                "subject": domain,
                "confidence": 85,
                "data": {
                    "policy": dmarc_parsed.get("policy", "none") if dmarc_parsed else "none",
                    "rua": rua,
                },
            }
            findings.append(finding)
            upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    logger.info("DOMAIN_DNS_LOOKUP completed", job_id=job["id"], findings_count=len(findings))
    return findings


# =============================================================================
# TECHNIQUE: DOMAIN_WHOIS_RDAP_LOOKUP (V1)
# =============================================================================

def execute_domain_whois_rdap_lookup(job: dict) -> list[dict]:
    """
    V1 DOMAIN_WHOIS_RDAP_LOOKUP - RDAP with provider abstraction.
    
    Provider chain:
    1. IanaRdapProvider (IANA bootstrap servers)
    2. MockRdapProvider (fallback for tests)
    
    Security mitigations:
    - Domain validation before lookup
    - Trusted RDAP servers only (IANA bootstrap)
    - Rate limiting (10 req/min)
    
    Produces FindingTypes (V1 schema):
    - DOMAIN_REGISTRAR   (registrar name)
    - DOMAIN_LIFECYCLE   (created_at, expires_at)
    - DOMAIN_STATUS      (status flags)
    - DOMAIN_WHOIS_NAMESERVERS (nameservers)
    """
    from worker_app.security import validate_domain_for_osint
    from worker_app.rdap_providers import rdap_lookup, RdapParser
    
    domain = job["target_value"]
    params = job["params_json"]
    
    # Security: Validate domain first
    validation = validate_domain_for_osint(domain)
    if not validation["valid"]:
        raise ValueError(f"Invalid domain for OSINT: {validation['reason']}")
    if validation["blocked"]:
        raise ValueError(f"Blocked domain: {validation['reason']}")
    
    # Rate limit check (technique + per-domain throttle)
    rate_limited_request("domain_whois_rdap_lookup", domain=domain)
    
    logger.info("DOMAIN_WHOIS_RDAP_LOOKUP starting", job_id=job["id"], domain=domain)
    
    # ==========================================================================
    # RDAP Lookup via Provider Chain
    # ==========================================================================
    timeout = params.get("timeout", 10)
    rdap_result = rdap_lookup(domain, timeout=timeout)
    
    # ==========================================================================
    # RAW EVIDENCE (V1 format)
    # ==========================================================================
    raw_data = {
        "domain": domain,
        "rdap_server": rdap_result.get("rdap_server"),
        "response": rdap_result.get("response"),
        "source": rdap_result.get("source"),
        "success": rdap_result.get("success"),
        "error": rdap_result.get("error"),
        "queried_at": datetime.utcnow().isoformat() + "Z",
    }
    
    # Store raw evidence FIRST (immutable)
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source=rdap_result.get("source", "rdap"),
        data=raw_data,
        retrieval_meta={
            "rdap_server": rdap_result.get("rdap_server"),
            "timeout": timeout,
        },
    )
    
    # ==========================================================================
    # NORMALIZE TO FINDINGS (V1 schema)
    # ==========================================================================
    findings = []
    
    if not rdap_result["success"] or not rdap_result["response"]:
        logger.warning("RDAP lookup failed", domain=domain, error=rdap_result.get("error"))
        return findings
    
    response = rdap_result["response"]
    is_mock = response.get("_mock", False)
    base_confidence = 70 if is_mock else 80
    
    # DOMAIN_REGISTRAR
    registrar = RdapParser.extract_registrar(response)
    if registrar and registrar.get("name"):
        finding = {
            "finding_type": "DOMAIN_REGISTRAR",
            "subject": domain,
            "confidence": base_confidence,
            "data": {
                "name": registrar["name"],
            },
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # DOMAIN_LIFECYCLE (V1: created_at, expires_at)
    dates = RdapParser.extract_dates(response)
    if dates.get("created_at") or dates.get("expires_at"):
        finding = {
            "finding_type": "DOMAIN_LIFECYCLE",
            "subject": domain,
            "confidence": base_confidence + 5,
            "data": {
                "created_at": dates.get("created_at"),
                "expires_at": dates.get("expires_at"),
            },
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # DOMAIN_STATUS
    status = RdapParser.extract_status(response)
    if status:
        finding = {
            "finding_type": "DOMAIN_STATUS",
            "subject": domain,
            "confidence": base_confidence + 5,
            "data": {"status": status},
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    # DOMAIN_WHOIS_NAMESERVERS
    nameservers = RdapParser.extract_nameservers(response)
    if nameservers:
        finding = {
            "finding_type": "DOMAIN_WHOIS_NAMESERVERS",
            "subject": domain,
            "confidence": base_confidence + 5,
            "data": {"nameservers": nameservers},
        }
        findings.append(finding)
        upsert_finding(workspace_id=job["workspace_id"], target_id=job["target_id"], job_id=job["id"], **finding)
    
    logger.info("DOMAIN_WHOIS_RDAP_LOOKUP completed", job_id=job["id"], findings_count=len(findings))
    return findings


# =============================================================================
# NOOP Lookup (Testing)
# =============================================================================

def execute_noop_lookup(job: dict) -> list[dict]:
    """NOOP technique for testing the job pipeline."""
    import random
    
    target = job["target_value"]
    params = job["params_json"]
    delay = params.get("delay", 0.5)
    
    logger.info("NOOP lookup", job_id=job["id"], target=target, delay=delay)
    time.sleep(delay)
    
    raw_data = {
        "target": target,
        "technique": "noop_lookup",
        "timestamp": datetime.utcnow().isoformat(),
        "source": "noop_test",
        "fake_data": {
            "message": "This is a test lookup",
            "random_value": random.randint(1000, 9999),
            "params_received": params,
        },
    }
    
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="noop_test",
        data=raw_data,
        retrieval_meta={"delay": delay, "type": "noop"},
    )
    
    findings = []
    finding = {
        "finding_type": "RAW_DATA",
        "subject": target,
        "confidence": 100,
        "data": {
            "type": "noop_test",
            "message": f"NOOP lookup completed for {target}",
            "random_id": raw_data["fake_data"]["random_value"],
        },
    }
    findings.append(finding)
    upsert_finding(
        workspace_id=job["workspace_id"],
        target_id=job["target_id"],
        job_id=job["id"],
        **finding,
    )
    
    logger.info("NOOP lookup completed", job_id=job["id"], findings_count=len(findings))
    return findings


# =============================================================================
# TECHNIQUE: USERNAME_GITHUB_LOOKUP
# =============================================================================

def execute_username_github_lookup(job: dict) -> list[dict]:
    """
    V1 USERNAME_GITHUB_LOOKUP - GitHub profile lookup.
    
    API: https://api.github.com/users/{username}
    
    Rate limits:
    - Without token: 60 req/hour
    - With token: 5000 req/hour
    
    Produces FindingTypes:
    - USERNAME_IDENTITY (profile data)
    - USERNAME_ACTIVITY (repos, followers)
    """
    from worker_app.username_providers import GitHubProvider
    
    username = job["target_value"]
    params = job.get("params_json", {}) or {}
    
    # Validate username (basic)
    if not username or len(username) > 39:
        raise ValueError(f"Invalid GitHub username: {username}")
    if not all(c.isalnum() or c == '-' for c in username):
        raise ValueError(f"Invalid GitHub username characters: {username}")
    
    # Rate limit check
    rate_limited_request("username_github_lookup", domain=f"github:{username}")
    
    logger.info("USERNAME_GITHUB_LOOKUP starting", job_id=job["id"], username=username)
    
    # Get optional token from params
    token = params.get("github_token")
    timeout = params.get("timeout", 10)
    
    # Execute lookup
    provider = GitHubProvider(token=token, timeout=timeout)
    response = provider.lookup(username)
    
    # Handle rate limit errors
    if response.get("error") == "rate_limit_exceeded":
        raise Exception("GitHub rate limit exceeded - retry later")
    
    # Raw Evidence (always save, even for 404)
    evidence_data = {
        "source": "github",
        "endpoint": response.get("endpoint"),
        "status": response.get("status_code"),
        "headers": response.get("headers"),
        "body": response.get("body"),
        "fetched_at": response.get("fetched_at"),
    }
    
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="github_api",
        data=evidence_data,
    )
    
    # Normalize findings
    findings = provider.normalize(username, response)
    
    # Persist findings
    for finding in findings:
        upsert_finding(
            workspace_id=job["workspace_id"],
            target_id=job["target_id"],
            job_id=job["id"],
            **finding,
        )
    
    logger.info("USERNAME_GITHUB_LOOKUP completed", job_id=job["id"], findings_count=len(findings))
    return findings


# =============================================================================
# TECHNIQUE: USERNAME_REDDIT_LOOKUP
# =============================================================================

def execute_username_reddit_lookup(job: dict) -> list[dict]:
    """
    V1 USERNAME_REDDIT_LOOKUP - Reddit profile lookup.
    
    API: https://www.reddit.com/user/{username}/about.json
    
    Rate limits:
    - ~1 request per 2-3 seconds per IP
    - Requires proper User-Agent
    
    Produces FindingTypes:
    - USERNAME_IDENTITY (profile data)
    - USERNAME_ACTIVITY (karma metrics)
    """
    from worker_app.username_providers import RedditProvider
    
    username = job["target_value"]
    params = job.get("params_json", {}) or {}
    
    # Validate username (Reddit rules: 3-20 chars, alphanumeric + underscore)
    if not username or len(username) < 3 or len(username) > 20:
        raise ValueError(f"Invalid Reddit username length: {username}")
    if not all(c.isalnum() or c == '_' for c in username):
        raise ValueError(f"Invalid Reddit username characters: {username}")
    
    # Rate limit check (Reddit is stricter)
    rate_limited_request("username_reddit_lookup", domain=f"reddit:{username}")
    
    logger.info("USERNAME_REDDIT_LOOKUP starting", job_id=job["id"], username=username)
    
    timeout = params.get("timeout", 10)
    
    # Execute lookup
    provider = RedditProvider(timeout=timeout)
    response = provider.lookup(username)
    
    # Handle rate limit errors
    if response.get("error") == "rate_limit_exceeded":
        raise Exception("Reddit rate limit exceeded - retry later")
    
    # Raw Evidence (always save, even for 404)
    evidence_data = {
        "source": "reddit",
        "endpoint": response.get("endpoint"),
        "status": response.get("status_code"),
        "headers": response.get("headers"),
        "body": response.get("body"),
        "fetched_at": response.get("fetched_at"),
    }
    
    store_raw_evidence(
        workspace_id=job["workspace_id"],
        job_id=job["id"],
        source="reddit_api",
        data=evidence_data,
    )
    
    # Normalize findings
    findings = provider.normalize(username, response)
    
    # Persist findings
    for finding in findings:
        upsert_finding(
            workspace_id=job["workspace_id"],
            target_id=job["target_id"],
            job_id=job["id"],
            **finding,
        )
    
    logger.info("USERNAME_REDDIT_LOOKUP completed", job_id=job["id"], findings_count=len(findings))
    return findings


# =============================================================================
# Legacy Techniques (aliases for backward compatibility)
# =============================================================================

def execute_dns_lookup(job: dict) -> list[dict]:
    """Legacy DNS lookup - delegates to DOMAIN_DNS_LOOKUP."""
    return execute_domain_dns_lookup(job)


def execute_whois_lookup(job: dict) -> list[dict]:
    """Legacy WHOIS lookup - delegates to DOMAIN_WHOIS_RDAP_LOOKUP."""
    return execute_domain_whois_rdap_lookup(job)


# =============================================================================
# Technique Router
# =============================================================================

TECHNIQUE_HANDLERS = {
    # Tier 1 - Domain
    "domain_dns_lookup": execute_domain_dns_lookup,
    "domain_whois_rdap_lookup": execute_domain_whois_rdap_lookup,
    
    # Tier 1 - Username
    "username_github_lookup": execute_username_github_lookup,
    "username_reddit_lookup": execute_username_reddit_lookup,
    
    # Testing
    "noop_lookup": execute_noop_lookup,
    
    # Legacy (backward compatibility)
    "dns_lookup": execute_dns_lookup,
    "whois_lookup": execute_whois_lookup,
}


# =============================================================================
# Unified Task Executor
# =============================================================================

class OSINTTask(Task):
    """Base task with retry and timeout handling."""
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
    4. Execute technique (with rate limiting)
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
        try:
            job = rehydrate_job(job_id)
            if job["attempt"] < job["max_attempts"]:
                update_job_retrying(job_id, "TIMEOUT", "Task exceeded time limit")
                raise
            else:
                update_job_dead_letter(job_id, "TIMEOUT", "Task exceeded time limit")
        except Exception:
            update_job_failed(job_id, "TIMEOUT", "Task exceeded time limit")
        
        return {"job_id": job_id, "status": "FAILED", "error": "timeout"}
        
    except Exception as e:
        error_code = type(e).__name__
        error_message = str(e)
        
        logger.error("Job failed", job_id=job_id, error=error_message)
        
        try:
            job = rehydrate_job(job_id)
            if job["attempt"] < job["max_attempts"]:
                update_job_retrying(job_id, error_code, error_message)
                raise
            else:
                update_job_dead_letter(job_id, error_code, error_message)
        except ValueError:
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
        "techniques": list(TECHNIQUE_HANDLERS.keys()),
    }
