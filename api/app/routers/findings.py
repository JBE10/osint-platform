"""Findings endpoints - Query normalized OSINT results."""
from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_viewer
from app.models.workspace import WorkspaceMember
from app.models.finding import Finding

router = APIRouter(prefix="/workspaces/{workspace_id}/findings", tags=["findings"])


# =============================================================================
# Schemas
# =============================================================================

class FindingResponse(BaseModel):
    """Finding response."""
    id: UUID
    workspace_id: UUID
    target_id: UUID
    job_id: UUID
    finding_type: str
    subject: str
    confidence: int
    data_json: dict
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class FindingStats(BaseModel):
    """Aggregated finding statistics."""
    total: int
    by_type: dict[str, int]
    by_confidence: dict[str, int]


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=list[FindingResponse])
def list_findings(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    finding_type: Optional[str] = None,
    subject: Optional[str] = None,
    target_id: Optional[UUID] = None,
    job_id: Optional[UUID] = None,
    min_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    """
    List findings in workspace. Requires VIEWER role.
    
    Supports filtering by:
    - finding_type: Filter by type (e.g., DOMAIN_DNS_RECORD)
    - subject: Filter by subject (exact match)
    - target_id: Filter by target
    - job_id: Filter by job
    - min_confidence: Minimum confidence score (0-100)
    """
    query = select(Finding).where(
        Finding.workspace_id == workspace_id,
        Finding.confidence >= min_confidence,
    )
    
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if subject:
        query = query.where(Finding.subject == subject)
    if target_id:
        query = query.where(Finding.target_id == target_id)
    if job_id:
        query = query.where(Finding.job_id == job_id)
    
    query = query.order_by(Finding.last_seen_at.desc()).limit(limit).offset(offset)
    
    findings = db.execute(query).scalars().all()
    return findings


@router.get("/search", response_model=list[FindingResponse])
def search_findings(
    workspace_id: UUID,
    q: str,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    limit: int = Query(50, le=500),
):
    """
    Search findings by subject (partial match). Requires VIEWER role.
    """
    query = select(Finding).where(
        Finding.workspace_id == workspace_id,
        Finding.subject.ilike(f"%{q}%"),
    ).order_by(Finding.last_seen_at.desc()).limit(limit)
    
    findings = db.execute(query).scalars().all()
    return findings


@router.get("/stats", response_model=FindingStats)
def get_finding_stats(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    target_id: Optional[UUID] = None,
):
    """
    Get aggregated finding statistics. Requires VIEWER role.
    """
    base_filter = [Finding.workspace_id == workspace_id]
    if target_id:
        base_filter.append(Finding.target_id == target_id)
    
    # Total count
    total = db.execute(
        select(func.count(Finding.id)).where(*base_filter)
    ).scalar() or 0
    
    # Count by type
    type_counts = db.execute(
        select(Finding.finding_type, func.count(Finding.id))
        .where(*base_filter)
        .group_by(Finding.finding_type)
    ).all()
    by_type = {row[0]: row[1] for row in type_counts}
    
    # Count by confidence buckets
    confidence_buckets = {
        "high": db.execute(
            select(func.count(Finding.id)).where(*base_filter, Finding.confidence >= 80)
        ).scalar() or 0,
        "medium": db.execute(
            select(func.count(Finding.id)).where(*base_filter, Finding.confidence >= 50, Finding.confidence < 80)
        ).scalar() or 0,
        "low": db.execute(
            select(func.count(Finding.id)).where(*base_filter, Finding.confidence < 50)
        ).scalar() or 0,
    }
    
    return FindingStats(
        total=total,
        by_type=by_type,
        by_confidence=confidence_buckets,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    workspace_id: UUID,
    finding_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get finding details. Requires VIEWER role."""
    finding = db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return finding

