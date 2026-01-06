"""MinIO storage service for raw evidence."""
import json
import os
from datetime import datetime
from typing import Any
from uuid import UUID

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


def store_raw_evidence(
    job_id: UUID,
    workspace_id: UUID,
    job_type: str,
    raw_data: dict[str, Any],
) -> str:
    """
    Store raw evidence in MinIO before normalization.
    
    Path format: {workspace_id}/{job_type}/{date}/{job_id}.json
    
    Returns: The path where evidence was stored
    """
    client = get_minio_client()
    ensure_bucket_exists(client)
    
    # Generate path
    date_str = datetime.utcnow().strftime("%Y/%m/%d")
    object_name = f"{workspace_id}/{job_type}/{date_str}/{job_id}.json"
    
    # Serialize data
    data_bytes = json.dumps(raw_data, indent=2, default=str).encode("utf-8")
    
    try:
        from io import BytesIO
        client.put_object(
            MINIO_BUCKET,
            object_name,
            BytesIO(data_bytes),
            length=len(data_bytes),
            content_type="application/json",
        )
        logger.info("Stored raw evidence", path=object_name, size=len(data_bytes))
        return f"s3://{MINIO_BUCKET}/{object_name}"
    except S3Error as e:
        logger.error("Failed to store evidence", path=object_name, error=str(e))
        raise


def get_raw_evidence(path: str) -> dict[str, Any] | None:
    """
    Retrieve raw evidence from MinIO.
    
    Args:
        path: S3 path (s3://bucket/object)
        
    Returns:
        The raw evidence data or None if not found
    """
    if not path.startswith("s3://"):
        return None
    
    # Parse path
    path_parts = path[5:].split("/", 1)
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
        logger.error("Failed to retrieve evidence", path=path, error=str(e))
        return None


def delete_raw_evidence(path: str) -> bool:
    """Delete raw evidence from MinIO."""
    if not path.startswith("s3://"):
        return False
    
    path_parts = path[5:].split("/", 1)
    if len(path_parts) != 2:
        return False
    
    bucket, object_name = path_parts
    client = get_minio_client()
    
    try:
        client.remove_object(bucket, object_name)
        logger.info("Deleted evidence", path=path)
        return True
    except S3Error as e:
        logger.error("Failed to delete evidence", path=path, error=str(e))
        return False

