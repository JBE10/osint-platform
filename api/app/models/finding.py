"""Finding model - Normalized OSINT results."""
import hashlib
import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import String, DateTime, Integer, ForeignKey, func, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class FindingType(str, Enum):
    """Normalized finding types."""
    # DNS
    DOMAIN_DNS_RECORD = "DOMAIN_DNS_RECORD"
    DOMAIN_NAMESERVER = "DOMAIN_NAMESERVER"
    
    # WHOIS
    DOMAIN_REGISTRAR = "DOMAIN_REGISTRAR"
    DOMAIN_REGISTRATION = "DOMAIN_REGISTRATION"
    DOMAIN_CONTACT = "DOMAIN_CONTACT"
    
    # Email
    EMAIL_VALID = "EMAIL_VALID"
    EMAIL_DELIVERABLE = "EMAIL_DELIVERABLE"
    EMAIL_PROVIDER = "EMAIL_PROVIDER"
    
    # Network
    IP_GEOLOCATION = "IP_GEOLOCATION"
    IP_ASN = "IP_ASN"
    PORT_OPEN = "PORT_OPEN"
    SERVICE_BANNER = "SERVICE_BANNER"
    
    # Social
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    USERNAME_FOUND = "USERNAME_FOUND"
    
    # Security
    BREACH_ENTRY = "BREACH_ENTRY"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    
    # Generic
    RAW_DATA = "RAW_DATA"


def generate_finding_fingerprint(
    workspace_id: uuid.UUID,
    finding_type: str,
    subject: str,
    data: dict,
) -> str:
    """
    Generate finding fingerprint for deduplication.
    
    Same (workspace, type, subject, stable_data) = same finding = upsert.
    """
    # Extract stable fields from data (exclude timestamps, etc.)
    stable_data = {k: v for k, v in data.items() if k not in ("timestamp", "ttl", "cached_at")}
    data_str = json.dumps(stable_data, sort_keys=True, separators=(',', ':'), default=str)
    
    composite = f"{workspace_id}{finding_type}{subject}{data_str}"
    return hashlib.sha256(composite.encode()).hexdigest()


class Finding(Base):
    """
    Finding model - Normalized OSINT results.
    
    Design principles:
    - Normalized schema for querying across jobs
    - Fingerprint for deduplication (same finding = update, not duplicate)
    - Confidence score for reliability ranking
    - Correlatable subject field
    
    V1 Schema (minimum):
    {
      "finding_type": "DOMAIN_DNS_RECORD",
      "subject": "example.com",
      "confidence": 90,
      "data": {
        "record_type": "MX",
        "value": "mail.example.com",
        "ttl": 3600
      }
    }
    """
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_workspace_type", "workspace_id", "finding_type"),
        Index("ix_findings_subject", "subject"),
        Index("ix_findings_job", "job_id"),
        Index("ix_findings_target", "target_id"),
        UniqueConstraint("workspace_id", "finding_fingerprint", name="uq_findings_fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True  # Future: FK to investigations
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    
    # Finding definition
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=False, index=True)  # Correlatable identifier
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)  # 0-100
    
    # Flexible data payload
    data_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Deduplication
    finding_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    # Temporal tracking (for changes over time)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    job = relationship("Job", back_populates="findings")
    target = relationship("Target", back_populates="findings")
    
    @classmethod
    def create_with_fingerprint(
        cls,
        workspace_id: uuid.UUID,
        target_id: uuid.UUID,
        job_id: uuid.UUID,
        finding_type: str,
        subject: str,
        confidence: int,
        data: dict,
        investigation_id: Optional[uuid.UUID] = None,
    ) -> "Finding":
        """Create a finding with auto-generated fingerprint."""
        fingerprint = generate_finding_fingerprint(workspace_id, finding_type, subject, data)
        return cls(
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            target_id=target_id,
            job_id=job_id,
            finding_type=finding_type,
            subject=subject,
            confidence=confidence,
            data_json=data,
            finding_fingerprint=fingerprint,
        )

