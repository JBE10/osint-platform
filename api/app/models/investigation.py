"""Investigation model - A specific inquiry within a workspace."""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Enum, ForeignKey, String, Text, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.job import Job
    from app.models.target import Target
    from app.models.workspace import Workspace


class InvestigationStatus(str, PyEnum):
    """Investigation status values."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"
    CANCELLED = "CANCELLED"


class Investigation(Base):
    """Investigation model representing a specific inquiry.
    
    An investigation belongs to a workspace and contains targets and jobs.
    It tracks the status and progress of an OSINT inquiry.
    """
    
    __tablename__ = "investigations"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Status
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=InvestigationStatus.DRAFT.value,
        index=True,
    )
    
    # Ownership
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    extra_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        return f"<Investigation(id={self.id!r}, name={self.name!r}, status={self.status!r})>"
