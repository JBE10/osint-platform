"""Job model - Source of truth for OSINT tasks."""
import hashlib
import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, func, Index, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class JobStatus(str, Enum):
    """
    Finite state machine for jobs.
    
    CREATED → QUEUED → RUNNING → SUCCEEDED
                         ↓
                      RETRYING → FAILED → DEAD_LETTER
                         ↑_________|
    """
    CREATED = "CREATED"          # Job persistido, aún no enviado a Celery
    QUEUED = "QUEUED"            # Enviado al broker
    RUNNING = "RUNNING"          # Worker lo tomó
    RETRYING = "RETRYING"        # Falló pero reintentará
    SUCCEEDED = "SUCCEEDED"      # Final feliz
    FAILED = "FAILED"            # Error no recuperable
    DEAD_LETTER = "DEAD_LETTER"  # Agotó reintentos
    CANCELLED = "CANCELLED"      # Cancelado manualmente


class TechniqueCode(str, Enum):
    """
    OSINT technique codes.
    
    Naming: {category}_{action}
    Each technique produces specific FindingTypes.
    """
    # ==========================================================================
    # Testing
    # ==========================================================================
    NOOP_LOOKUP = "noop_lookup"  # Dummy technique for testing
    
    # ==========================================================================
    # Domain Techniques (Tier 1 - Recommended)
    # ==========================================================================
    # DNS lookup: A/AAAA/CNAME/NS/MX/TXT + SPF/DMARC parsing
    DOMAIN_DNS_LOOKUP = "domain_dns_lookup"
    
    # WHOIS/RDAP lookup: registrar, dates, status, nameservers
    DOMAIN_WHOIS_RDAP_LOOKUP = "domain_whois_rdap_lookup"
    
    # ==========================================================================
    # Domain Techniques (Tier 2 - Future)
    # ==========================================================================
    SUBDOMAIN_ENUM = "subdomain_enum"        # Subdomain enumeration
    CERTIFICATE_TRANSPARENCY = "cert_transparency"  # CT log search
    
    # ==========================================================================
    # Email Techniques (Tier 1)
    # ==========================================================================
    EMAIL_MX_SPF_DMARC_CORRELATION = "email_mx_spf_dmarc_correlation"  # Passive domain analysis
    EMAIL_BREACH_LOOKUP = "email_breach_lookup"      # Breach database check
    
    # Email Techniques (Legacy)
    EMAIL_VERIFY = "email_verify"  # Deprecated - use EMAIL_MX_SPF_DMARC_CORRELATION
    
    # ==========================================================================
    # Network Techniques
    # ==========================================================================
    PORT_SCAN = "port_scan"                  # TCP port scan
    
    # ==========================================================================
    # Web Techniques
    # ==========================================================================
    SCREENSHOT = "screenshot"                # Web page screenshot
    
    # ==========================================================================
    # Username Techniques (Tier 1)
    # ==========================================================================
    USERNAME_GITHUB_LOOKUP = "username_github_lookup"    # GitHub profile lookup
    USERNAME_REDDIT_LOOKUP = "username_reddit_lookup"    # Reddit profile lookup
    
    # ==========================================================================
    # Social Techniques (Legacy)
    # ==========================================================================
    SOCIAL_LOOKUP = "social_lookup"          # Generic social media search
    
    # ==========================================================================
    # Security Techniques
    # ==========================================================================
    BREACH_CHECK = "breach_check"            # Breach database check
    
    # ==========================================================================
    # Legacy (deprecated, kept for compatibility)
    # ==========================================================================
    DNS_LOOKUP = "dns_lookup"                # Use DOMAIN_DNS_LOOKUP
    WHOIS_LOOKUP = "whois_lookup"            # Use DOMAIN_WHOIS_RDAP_LOOKUP


# Valid state transitions
VALID_TRANSITIONS = {
    JobStatus.CREATED: [JobStatus.QUEUED, JobStatus.CANCELLED],
    JobStatus.QUEUED: [JobStatus.RUNNING, JobStatus.CANCELLED],
    JobStatus.RUNNING: [JobStatus.SUCCEEDED, JobStatus.RETRYING, JobStatus.FAILED],
    JobStatus.RETRYING: [JobStatus.QUEUED],  # Re-enqueue
    JobStatus.SUCCEEDED: [],  # Terminal
    JobStatus.FAILED: [JobStatus.DEAD_LETTER, JobStatus.QUEUED],  # Can manually re-queue
    JobStatus.DEAD_LETTER: [JobStatus.QUEUED],  # Can manually re-queue
    JobStatus.CANCELLED: [],  # Terminal
}


def canonical_json(obj: dict) -> str:
    """Generate canonical JSON string for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), default=str)


def generate_idempotency_key(
    workspace_id: uuid.UUID,
    target_id: uuid.UUID,
    technique_code: str,
    params: dict,
    version: str = "v1",
) -> str:
    """
    Generate deterministic idempotency key.
    
    Formula: sha256(workspace_id + target_id + technique_code + canonical_json(params) + version)
    Same input = same key = prevents duplicate jobs.
    """
    data = f"{workspace_id}{target_id}{technique_code}{canonical_json(params or {})}{version}"
    return hashlib.sha256(data.encode()).hexdigest()


class Job(Base):
    """
    Job model - Source of truth for all OSINT tasks.
    
    Design principles:
    - Celery is just the executor; this table owns the state
    - Raw evidence stored separately in raw_evidence table (linked to MinIO)
    - Findings normalized in findings table for querying
    - Idempotency key prevents duplicate jobs
    """
    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_workspace_status", "workspace_id", "status"),
        Index("ix_jobs_target", "target_id"),
        CheckConstraint(
            "status IN ('CREATED', 'QUEUED', 'RUNNING', 'RETRYING', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER', 'CANCELLED')",
            name="ck_jobs_status"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True  # Future: FK to investigations table
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    
    # Job definition
    technique_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=JobStatus.CREATED.value, index=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=5)  # 1=highest, 10=lowest
    
    # Retry tracking
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    
    # Idempotency (prevents duplicate jobs)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    
    # Parameters (input)
    params_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Timestamps
    scheduled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)  # Future scheduling
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    # Error tracking
    error_code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Observability
    trace_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # For distributed tracing
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="jobs")
    raw_evidences = relationship("RawEvidence", back_populates="job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")

    def can_transition_to(self, new_status: JobStatus) -> bool:
        """Check if transition to new_status is valid."""
        current = JobStatus(self.status)
        return new_status in VALID_TRANSITIONS.get(current, [])
    
    def transition_to(self, new_status: JobStatus) -> bool:
        """Attempt state transition. Returns True if successful."""
        if not self.can_transition_to(new_status):
            return False
        self.status = new_status.value
        
        # Update timestamps based on state
        now = datetime.utcnow()
        if new_status == JobStatus.RUNNING:
            self.started_at = now
            self.attempt += 1
        elif new_status in (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.DEAD_LETTER, JobStatus.CANCELLED):
            self.finished_at = now
        
        return True
    
    @property
    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return self.attempt < self.max_attempts
    
    @property
    def should_dead_letter(self) -> bool:
        """Check if job should go to dead letter queue."""
        return self.attempt >= self.max_attempts
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate job duration in seconds."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
    
    @property
    def is_terminal(self) -> bool:
        """Check if job is in a terminal state."""
        return self.status in (
            JobStatus.SUCCEEDED.value,
            JobStatus.CANCELLED.value,
            JobStatus.DEAD_LETTER.value,
        )
