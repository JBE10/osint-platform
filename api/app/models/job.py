"""Job model - Source of truth for OSINT tasks."""
import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, func, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class JobStatus(str, Enum):
    """Finite state machine for jobs."""
    PENDING = "PENDING"      # Created, not yet queued
    QUEUED = "QUEUED"        # Sent to Celery
    RUNNING = "RUNNING"      # Being executed
    COMPLETED = "COMPLETED"  # Success
    FAILED = "FAILED"        # Error (may retry)
    CANCELLED = "CANCELLED"  # Manually cancelled


class JobType(str, Enum):
    """Types of OSINT jobs."""
    DNS_LOOKUP = "dns_lookup"
    WHOIS_LOOKUP = "whois_lookup"
    EMAIL_VERIFY = "email_verify"
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCAN = "port_scan"
    SCREENSHOT = "screenshot"


# Valid state transitions
VALID_TRANSITIONS = {
    JobStatus.PENDING: [JobStatus.QUEUED, JobStatus.CANCELLED],
    JobStatus.QUEUED: [JobStatus.RUNNING, JobStatus.FAILED, JobStatus.CANCELLED],
    JobStatus.RUNNING: [JobStatus.COMPLETED, JobStatus.FAILED],
    JobStatus.COMPLETED: [],  # Terminal
    JobStatus.FAILED: [JobStatus.QUEUED],  # Can retry
    JobStatus.CANCELLED: [],  # Terminal
}


def generate_idempotency_key(
    workspace_id: uuid.UUID,
    target_id: uuid.UUID,
    job_type: str,
    config: dict,
) -> str:
    """
    Generate deterministic idempotency key.
    Same input = same key = prevents duplicate jobs.
    """
    # Sort config keys for deterministic hash
    config_str = str(sorted(config.items())) if config else ""
    data = f"{workspace_id}:{target_id}:{job_type}:{config_str}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


class Job(Base):
    """
    Job model - Source of truth for all OSINT tasks.
    Celery is just the executor; this table owns the state.
    """
    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_workspace_status", "workspace_id", "status"),
        Index("ix_jobs_target_status", "target_id", "status"),
        Index("ix_jobs_idempotency", "idempotency_key", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    
    # Job type and status
    job_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=JobStatus.PENDING.value, index=True)
    
    # Idempotency (prevents duplicate jobs)
    idempotency_key: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    
    # Celery task tracking
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    
    # Configuration (input params)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Results
    result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Raw evidence location (MinIO path)
    raw_evidence_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Retry tracking
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    queued_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="jobs")

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
        if new_status == JobStatus.QUEUED:
            self.queued_at = now
        elif new_status == JobStatus.RUNNING:
            self.started_at = now
        elif new_status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            self.completed_at = now
        
        return True
    
    @property
    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return (
            self.status == JobStatus.FAILED.value
            and self.retry_count < self.max_retries
        )
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate job duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
