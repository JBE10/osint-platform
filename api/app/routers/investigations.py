"""Investigation endpoints - Manage OSINT investigations and export."""
from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_viewer, require_analyst
from app.core.audit import create_audit_log
from app.models.workspace import WorkspaceMember
from app.models.investigation import Investigation
from app.models.target import Target
from app.models.finding import Finding
from app.models.job import Job

router = APIRouter(prefix="/workspaces/{workspace_id}/investigations", tags=["investigations"])


# =============================================================================
# Schemas
# =============================================================================

class InvestigationCreate(BaseModel):
    """Create investigation request."""
    name: str
    description: Optional[str] = None
    tags: list[str] = []


class InvestigationResponse(BaseModel):
    """Investigation response."""
    id: str
    workspace_id: str
    name: str
    description: Optional[str]
    status: str
    created_by: str
    assigned_to: Optional[str]
    tags: list[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class TargetExport(BaseModel):
    """Target in export format."""
    id: str
    type: str
    value: str
    findings: list[dict]


class InvestigationExport(BaseModel):
    """Full investigation export (per design spec)."""
    investigation: dict
    targets: list[TargetExport]
    generated_at: str


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=list[InvestigationResponse])
def list_investigations(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    """List investigations in workspace. Requires VIEWER role."""
    query = select(Investigation).where(
        Investigation.workspace_id == str(workspace_id),
        Investigation.deleted_at.is_(None),
    )
    
    if status:
        query = query.where(Investigation.status == status)
    
    query = query.order_by(Investigation.created_at.desc()).limit(limit).offset(offset)
    
    investigations = db.execute(query).scalars().all()
    return investigations


@router.post("", response_model=InvestigationResponse, status_code=201)
def create_investigation(
    workspace_id: UUID,
    data: InvestigationCreate,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Create new investigation. Requires ANALYST role."""
    import uuid as uuid_mod
    
    investigation = Investigation(
        id=str(uuid_mod.uuid4()).replace("-", ""),
        workspace_id=str(workspace_id),
        name=data.name,
        description=data.description,
        tags=data.tags,
        created_by=str(user.id),
        status="DRAFT",
    )
    
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    
    create_audit_log(
        db=db,
        action="investigation.create",
        resource_type="investigation",
        resource_id=None,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        details={"name": data.name},
    )
    
    return investigation


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    workspace_id: UUID,
    investigation_id: str,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get investigation details. Requires VIEWER role."""
    investigation = db.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.workspace_id == str(workspace_id),
            Investigation.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    return investigation


@router.get("/{investigation_id}/export")
def export_investigation(
    workspace_id: UUID,
    investigation_id: str,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """
    Export investigation as structured JSON for auditing.
    
    Returns complete investigation with all targets and findings
    in auditable format (per design spec V1).
    
    Requires VIEWER role.
    RBAC enforced, audit logged.
    """
    # Get investigation
    investigation = db.execute(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.workspace_id == str(workspace_id),
            Investigation.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    # Get targets for this investigation
    target_query = select(Target).where(
        Target.workspace_id == workspace_id,
        Target.investigation_id == investigation_id,
    )
    # Handle soft delete if column exists
    if hasattr(Target, 'deleted_at'):
        target_query = target_query.where(Target.deleted_at.is_(None))
    
    targets = db.execute(target_query).scalars().all()
    
    # Build export structure (per design spec)
    export_targets = []
    
    for target in targets:
        # Get findings for this target
        findings = db.execute(
            select(Finding).where(
                Finding.workspace_id == workspace_id,
                Finding.target_id == target.id,
            ).order_by(Finding.finding_type, Finding.last_seen_at.desc())
        ).scalars().all()
        
        target_export = {
            "id": str(target.id),
            "type": target.target_type.upper() if target.target_type else "UNKNOWN",
            "value": target.value,
            "findings": [
                {
                    "finding_type": f.finding_type,
                    "confidence": f.confidence,
                    "data": f.data_json,
                    "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
                    "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                }
                for f in findings
            ],
        }
        export_targets.append(target_export)
    
    # Build final export (per design spec format)
    export = {
        "investigation": {
            "id": investigation.id,
            "name": investigation.name,
            "description": investigation.description,
            "status": investigation.status.value if hasattr(investigation.status, 'value') else str(investigation.status),
            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
            "started_at": investigation.started_at.isoformat() if investigation.started_at else None,
            "completed_at": investigation.completed_at.isoformat() if investigation.completed_at else None,
            "created_by": investigation.created_by,
            "tags": investigation.tags,
        },
        "targets": export_targets,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    # Audit log (per design spec)
    create_audit_log(
        db=db,
        action="investigation.export",
        resource_type="investigation",
        resource_id=None,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        details={"targets_count": len(export_targets)},
    )
    
    return export


@router.get("/{investigation_id}/findings")
def list_investigation_findings(
    workspace_id: UUID,
    investigation_id: str,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    finding_type: Optional[str] = None,
    min_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(100, le=500),
):
    """
    List all findings for an investigation.
    
    Aggregates findings across all targets in the investigation.
    Requires VIEWER role.
    """
    # Get target IDs for this investigation
    target_query = select(Target.id).where(
        Target.workspace_id == workspace_id,
        Target.investigation_id == investigation_id,
    )
    if hasattr(Target, 'deleted_at'):
        target_query = target_query.where(Target.deleted_at.is_(None))
    
    target_ids = db.execute(target_query).scalars().all()
    
    if not target_ids:
        return []
    
    # Get findings for these targets
    query = select(Finding).where(
        Finding.workspace_id == workspace_id,
        Finding.target_id.in_(target_ids),
        Finding.confidence >= min_confidence,
    )
    
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    
    query = query.order_by(Finding.finding_type, Finding.last_seen_at.desc()).limit(limit)
    
    findings = db.execute(query).scalars().all()
    
    return [
        {
            "id": str(f.id),
            "finding_type": f.finding_type,
            "subject": f.subject,
            "confidence": f.confidence,
            "data": f.data_json,
            "target_id": str(f.target_id),
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        }
        for f in findings
    ]

