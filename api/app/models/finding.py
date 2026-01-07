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
    """
    Normalized finding types - STABLE V1 identifiers.
    
    Naming convention: DOMAIN_{SEMANTIC_MEANING}
    """
    # ==========================================================================
    # DNS Lookup Findings (DOMAIN_DNS_LOOKUP)
    # ==========================================================================
    DOMAIN_IP_ADDRESS = "DOMAIN_IP_ADDRESS"        # A/AAAA → IP (v4/v6)
    DOMAIN_NAMESERVER = "DOMAIN_NAMESERVER"        # NS record
    DOMAIN_CNAME = "DOMAIN_CNAME"                  # Canonical name alias
    DOMAIN_MAIL_SERVER = "DOMAIN_MAIL_SERVER"      # MX record
    DOMAIN_SPF_POLICY = "DOMAIN_SPF_POLICY"        # Parsed SPF from TXT
    DOMAIN_DMARC_POLICY = "DOMAIN_DMARC_POLICY"    # Parsed DMARC from TXT
    
    # ==========================================================================
    # WHOIS/RDAP Findings (DOMAIN_WHOIS_RDAP_LOOKUP) - V1
    # ==========================================================================
    DOMAIN_REGISTRAR = "DOMAIN_REGISTRAR"          # Registrar name
    DOMAIN_LIFECYCLE = "DOMAIN_LIFECYCLE"          # created_at, expires_at
    DOMAIN_STATUS = "DOMAIN_STATUS"                # Domain status flags
    DOMAIN_WHOIS_NAMESERVERS = "DOMAIN_WHOIS_NAMESERVERS"  # WHOIS nameservers
    
    # ==========================================================================
    # Email Findings (EMAIL_*)
    # ==========================================================================
    EMAIL_VALID = "EMAIL_VALID"
    EMAIL_DELIVERABLE = "EMAIL_DELIVERABLE"
    EMAIL_PROVIDER = "EMAIL_PROVIDER"                          # Mail provider detection
    EMAIL_DISPOSABLE = "EMAIL_DISPOSABLE"
    EMAIL_MAIL_INFRASTRUCTURE = "EMAIL_MAIL_INFRASTRUCTURE"    # MX hosts from domain
    EMAIL_SPF_POLICY = "EMAIL_SPF_POLICY"                      # SPF policy (mode, includes)
    EMAIL_DMARC_POLICY = "EMAIL_DMARC_POLICY"                  # DMARC policy (p, rua)
    EMAIL_BREACH_STATUS = "EMAIL_BREACH_STATUS"                # Breach check result
    # Legacy (deprecated)
    EMAIL_DOMAIN_CONFIG = "EMAIL_DOMAIN_CONFIG"
    EMAIL_BREACH = "EMAIL_BREACH"
    
    # ==========================================================================
    # Network Findings (IP_*, PORT_*, SERVICE_*)
    # ==========================================================================
    IP_GEOLOCATION = "IP_GEOLOCATION"
    IP_ASN = "IP_ASN"
    IP_REVERSE_DNS = "IP_REVERSE_DNS"
    PORT_OPEN = "PORT_OPEN"
    SERVICE_BANNER = "SERVICE_BANNER"
    SERVICE_VERSION = "SERVICE_VERSION"
    
    # ==========================================================================
    # Social Findings (SOCIAL_*, USERNAME_*)
    # ==========================================================================
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    USERNAME_FOUND = "USERNAME_FOUND"
    USERNAME_IDENTITY = "USERNAME_IDENTITY"    # Profile existence/data on platform
    USERNAME_ACTIVITY = "USERNAME_ACTIVITY"    # Activity metrics (repos, karma, etc)
    
    # ==========================================================================
    # Security Findings (SECURITY_*)
    # ==========================================================================
    SECURITY_BREACH = "SECURITY_BREACH"
    SECURITY_LEAK = "SECURITY_LEAK"
    SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
    
    # ==========================================================================
    # Generic (for testing/custom)
    # ==========================================================================
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
    # Extract stable fields from data (exclude timestamps, TTLs, etc.)
    volatile_keys = ("timestamp", "ttl", "cached_at", "query_time_ms", "last_checked")
    stable_data = {k: v for k, v in data.items() if k not in volatile_keys}
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
      "finding_type": "DOMAIN_DNS_A",
      "subject": "example.com",
      "confidence": 95,
      "data": {
        "ip": "93.184.216.34",
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
