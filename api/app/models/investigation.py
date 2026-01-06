"""Investigation model - A specific inquiry within a workspace."""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin
from shared.enums import InvestigationStatus

if TYPE_CHECKING:
    from app.models.job import Job
    from app.models.target import Target
    from app.models.workspace import Workspace


class Investigation(Base, TimestampMixin, SoftDeleteMixin):
    """Investigation model representing a specific inquiry.
    
    An investigation belongs to a workspace and contains targets and jobs.
    It tracks the status and progress of an OSINT inquiry.
    """
    
    __tablename__ = "investigations"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    
    # Foreign keys
    workspace_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Status
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, name="investigation_status"),
        nullable=False,
        default=InvestigationStatus.DRAFT,
        index=True,
    )
    
    # Ownership
    created_by: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Timestamps for status changes
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    
    # Relationships
    workspace: Mapped["Workspace"] = relationship(
        "Workspace",
        back_populates="investigations",
    )
    targets: Mapped[list["Target"]] = relationship(
        "Target",
        back_populates="investigation",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    jobs: Mapped[list["Job"]] = relationship(
        "Job",
        back_populates="investigation",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    
    def __repr__(self) -> str:
        return f"<Investigation(id={self.id!r}, name={self.name!r}, status={self.status.value!r})>"

