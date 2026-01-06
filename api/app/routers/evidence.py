"""Raw Evidence endpoints - Audit trail access."""
from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_viewer, require_admin
from app.core.storage import get_raw_evidence, list_job_evidence
from app.models.workspace import WorkspaceMember
from app.models.raw_evidence import RawEvidence

router = APIRouter(prefix="/workspaces/{workspace_id}/evidence", tags=["evidence"])


# =============================================================================
# Schemas
# =============================================================================

class RawEvidenceResponse(BaseModel):
    """Raw evidence metadata response."""
    id: UUID
    workspace_id: UUID
    job_id: UUID
    storage_uri: str
    content_type: str
    sha256: str
    size_bytes: Optional[int]
    source: str
    retrieval_meta_json: dict
    captured_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class RawEvidenceContent(BaseModel):
    """Raw evidence with content."""
    metadata: RawEvidenceResponse
    content: dict


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=list[RawEvidenceResponse])
def list_evidence(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    job_id: Optional[UUID] = None,
    source: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """
    List raw evidence metadata in workspace. Requires VIEWER role.
    """
    query = select(RawEvidence).where(RawEvidence.workspace_id == workspace_id)
    
    if job_id:
        query = query.where(RawEvidence.job_id == job_id)
    if source:
        query = query.where(RawEvidence.source == source)
    
    query = query.order_by(RawEvidence.captured_at.desc()).limit(limit).offset(offset)
    
    evidence = db.execute(query).scalars().all()
    return evidence


@router.get("/{evidence_id}", response_model=RawEvidenceResponse)
def get_evidence_metadata(
    workspace_id: UUID,
    evidence_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get evidence metadata. Requires VIEWER role."""
    evidence = db.execute(
        select(RawEvidence).where(
            RawEvidence.id == evidence_id,
            RawEvidence.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    return evidence


@router.get("/{evidence_id}/content", response_model=RawEvidenceContent)
def get_evidence_content(
    workspace_id: UUID,
    evidence_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_admin)],
):
    """
    Get evidence with full content from MinIO. Requires ADMIN role.
    
    NOTE: Admin role required because raw evidence may contain sensitive data.
    """
    evidence = db.execute(
        select(RawEvidence).where(
            RawEvidence.id == evidence_id,
            RawEvidence.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Fetch content from MinIO
    content = get_raw_evidence(evidence.storage_uri)
    
    if content is None:
        raise HTTPException(status_code=404, detail="Evidence content not found in storage")
    
    return RawEvidenceContent(
        metadata=evidence,
        content=content,
    )


@router.get("/job/{job_id}/files")
def list_job_evidence_files(
    workspace_id: UUID,
    job_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """
    List all evidence files for a job directly from MinIO. Requires VIEWER role.
    """
    files = list_job_evidence(workspace_id, job_id)
    return {"job_id": str(job_id), "files": files}

