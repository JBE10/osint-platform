"""Raw Evidence model - Immutable audit trail of OSINT data."""
import hashlib
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, func, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def calculate_sha256(content: bytes) -> str:
    """Calculate SHA256 hash of content."""
    return hashlib.sha256(content).hexdigest()


class RawEvidence(Base):
    """
    Raw Evidence model - Immutable audit trail.
    
    Design principles:
    - NEVER delete evidence (audit trail, legal defense)
    - Always store before processing
    - Raw response + metadata = full reproducibility
    
    Storage naming convention:
    s3://evidence/{workspace_id}/{job_id}/{source}_{timestamp}_{sha256[:8]}.json
    """
    __tablename__ = "raw_evidence"
    __table_args__ = (
        Index("ix_raw_evidence_job", "job_id"),
        Index("ix_raw_evidence_sha256", "sha256"),
        Index("ix_raw_evidence_workspace", "workspace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    
    # Storage location (MinIO)
    storage_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    
    # Content metadata
    content_type: Mapped[str] = mapped_column(String(100), nullable=False, default="application/json")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(nullable=True)
    
    # Source information
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "dns_resolver", "whois_api"
    
    # Retrieval metadata (how we got this data)
    retrieval_meta_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Example: {
    #   "url": "https://api.example.com/...",
    #   "method": "GET",
    #   "status_code": 200,
    #   "headers": {...},  # Response headers (no secrets)
    #   "duration_ms": 234,
    #   "resolver": "8.8.8.8",  # For DNS
    # }
    
    # Timestamp when data was captured (not when stored)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # When we stored it
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    job = relationship("Job", back_populates="raw_evidences")
    
    @classmethod
    def generate_storage_uri(
        cls,
        workspace_id: uuid.UUID,
        job_id: uuid.UUID,
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

