"""MinIO storage service for raw evidence - AUDIT TRAIL."""
import hashlib
import json
import os
from datetime import datetime
from typing import Any
from uuid import UUID
from io import BytesIO

from minio import Minio
from minio.error import S3Error
import structlog

logger = structlog.get_logger(__name__)

# Configuration
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minio123456")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "evidence")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

# Remove http:// prefix if present
if MINIO_ENDPOINT.startswith("http://"):
    MINIO_ENDPOINT = MINIO_ENDPOINT[7:]
elif MINIO_ENDPOINT.startswith("https://"):
    MINIO_ENDPOINT = MINIO_ENDPOINT[8:]


def get_minio_client() -> Minio:
    """Get MinIO client instance."""
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def ensure_bucket_exists(client: Minio, bucket: str = MINIO_BUCKET) -> None:
    """Ensure the bucket exists, create if not."""
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info("Created bucket", bucket=bucket)
    except S3Error as e:
        logger.error("Failed to ensure bucket", bucket=bucket, error=str(e))
        raise


def calculate_sha256(content: bytes) -> str:
    """Calculate SHA256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def generate_storage_uri(
    workspace_id: UUID,
    job_id: UUID,
    source: str,
    timestamp: datetime,
    sha256_hash: str,
) -> str:
    """
    Generate storage URI following naming convention.
    
    Format: {workspace_id}/{job_id}/{source}_{timestamp}_{sha256[:8]}.json
    """
    ts_str = timestamp.strftime("%Y%m%d_%H%M%S")
    return f"{workspace_id}/{job_id}/{source}_{ts_str}_{sha256_hash[:8]}.json"


def store_raw_evidence(
    workspace_id: UUID,
    job_id: UUID,
    source: str,
    raw_data: dict[str, Any],
    retrieval_meta: dict[str, Any] | None = None,
) -> tuple[str, str, int]:
    """
    Store raw evidence in MinIO.
    
    Naming convention: {workspace_id}/{job_id}/{source}_{timestamp}_{sha256[:8]}.json
    
    AUDIT TRAIL: Never modify or delete evidence.
    
    Args:
        workspace_id: Workspace UUID
        job_id: Job UUID
        source: Source identifier (e.g., "dns_resolver", "whois_cli")
        raw_data: Raw data to store
        retrieval_meta: Optional metadata about how data was retrieved
        
    Returns:
        Tuple of (storage_uri, sha256, size_bytes)
    """
    client = get_minio_client()
    ensure_bucket_exists(client)
    
    # Prepare data with metadata
    captured_at = datetime.utcnow()
    evidence_data = {
        **raw_data,
        "_evidence_meta": {
            "workspace_id": str(workspace_id),
            "job_id": str(job_id),
            "source": source,
            "captured_at": captured_at.isoformat(),
            "retrieval_meta": retrieval_meta or {},
        },
    }
    
    # Serialize
    content = json.dumps(evidence_data, indent=2, default=str).encode("utf-8")
    sha256_hash = calculate_sha256(content)
    size_bytes = len(content)
    
    # Generate path
    object_name = generate_storage_uri(workspace_id, job_id, source, captured_at, sha256_hash)
    storage_uri = f"s3://{MINIO_BUCKET}/{object_name}"
    
    try:
        client.put_object(
            MINIO_BUCKET,
            object_name,
            BytesIO(content),
            length=size_bytes,
            content_type="application/json",
        )
        logger.info(
            "Stored raw evidence",
            storage_uri=storage_uri,
            size=size_bytes,
            sha256=sha256_hash[:16],
        )
        return storage_uri, sha256_hash, size_bytes
    except S3Error as e:
        logger.error("Failed to store evidence", path=object_name, error=str(e))
        raise


def get_raw_evidence(storage_uri: str) -> dict[str, Any] | None:
    """
    Retrieve raw evidence from MinIO.
    
    Args:
        storage_uri: S3 path (s3://bucket/object)
        
    Returns:
        The raw evidence data or None if not found
    """
    if not storage_uri.startswith("s3://"):
        return None
    
    # Parse path
    path_parts = storage_uri[5:].split("/", 1)
    if len(path_parts) != 2:
        return None
    
    bucket, object_name = path_parts
    client = get_minio_client()
    
    try:
        response = client.get_object(bucket, object_name)
        data = json.loads(response.read().decode("utf-8"))
        response.close()
        response.release_conn()
        return data
    except S3Error as e:
        logger.error("Failed to retrieve evidence", path=storage_uri, error=str(e))
        return None


def list_job_evidence(workspace_id: UUID, job_id: UUID) -> list[dict[str, Any]]:
    """
    List all evidence files for a job.
    
    Returns list of dicts with: name, size, last_modified
    """
    client = get_minio_client()
    prefix = f"{workspace_id}/{job_id}/"
    
    try:
        objects = client.list_objects(MINIO_BUCKET, prefix=prefix)
        return [
            {
                "name": obj.object_name,
                "size": obj.size,
                "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                "storage_uri": f"s3://{MINIO_BUCKET}/{obj.object_name}",
            }
            for obj in objects
        ]
    except S3Error as e:
        logger.error("Failed to list evidence", prefix=prefix, error=str(e))
        return []


# NOTE: No delete function - evidence is NEVER deleted (audit trail)
