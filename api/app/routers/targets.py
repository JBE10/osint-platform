"""Target management endpoints with OSINT validators."""
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_viewer, require_analyst
from app.core.audit import create_audit_log
from app.core.validators import OSINTEmail, OSINTDomain, OSINTUsername, OSINTIPAddress
from app.models.workspace import WorkspaceMember
from app.models.target import Target, TargetType

router = APIRouter(prefix="/workspaces/{workspace_id}/targets", tags=["targets"])


# =============================================================================
# Schemas
# =============================================================================

class TargetCreate(BaseModel):
    """Generic target creation."""
    target_type: str
    value: str
    label: Optional[str] = None
    extra_data: dict = {}


class EmailTargetCreate(BaseModel):
    """Create target with validated email."""
    email: OSINTEmail
    label: Optional[str] = None


class DomainTargetCreate(BaseModel):
    """Create target with validated domain."""
    domain: OSINTDomain
    label: Optional[str] = None


class UsernameTargetCreate(BaseModel):
    """Create target with validated username."""
    username: OSINTUsername
    label: Optional[str] = None


class IPTargetCreate(BaseModel):
    """Create target with validated IP."""
    ip: OSINTIPAddress
    label: Optional[str] = None


class TargetResponse(BaseModel):
    id: UUID
    workspace_id: UUID
    target_type: str
    value: str
    label: Optional[str] = None
    extra_data: dict

    class Config:
        from_attributes = True


# =============================================================================
# Helper
# =============================================================================

def _create_target(
    db: Session,
    workspace_id: UUID,
    user_id: UUID,
    target_type: str,
    value: str,
    label: Optional[str],
    extra_data: dict,
    request: Request,
) -> Target:
    """Create and persist a target."""
    target = Target(
        workspace_id=workspace_id,
        created_by=user_id,
        target_type=target_type,
        value=value,
        label=label,
        extra_data=extra_data,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    
    # Audit
    create_audit_log(
        db=db,
        action="target.create",
        resource_type="target",
        resource_id=target.id,
        workspace_id=workspace_id,
        actor_user_id=user_id,
        request=request,
        details={"target_type": target_type, "value": value},
    )
    
    return target


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=list[TargetResponse])
def list_targets(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    target_type: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    """List targets. Requires VIEWER role."""
    query = select(Target).where(Target.workspace_id == workspace_id)
    
    if target_type:
        query = query.where(Target.target_type == target_type)
    
    query = query.order_by(Target.created_at.desc()).limit(limit).offset(offset)
    
    targets = db.execute(query).scalars().all()
    return targets


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    workspace_id: UUID,
    target_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get target details. Requires VIEWER role."""
    target = db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    return target


@router.post("/email", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_email_target(
    workspace_id: UUID,
    data: EmailTargetCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Create email target. Requires ANALYST role. Validates email format."""
    return _create_target(
        db=db,
        workspace_id=workspace_id,
        user_id=user.id,
        target_type=TargetType.EMAIL.value,
        value=data.email,
        label=data.label,
        extra_data={},
        request=request,
    )


@router.post("/domain", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_domain_target(
    workspace_id: UUID,
    data: DomainTargetCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Create domain target. Requires ANALYST role. Validates domain format."""
    return _create_target(
        db=db,
        workspace_id=workspace_id,
        user_id=user.id,
        target_type=TargetType.DOMAIN.value,
        value=data.domain,
        label=data.label,
        extra_data={},
        request=request,
    )


@router.post("/username", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_username_target(
    workspace_id: UUID,
    data: UsernameTargetCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Create username target. Requires ANALYST role. Validates username format."""
    return _create_target(
        db=db,
        workspace_id=workspace_id,
        user_id=user.id,
        target_type=TargetType.USERNAME.value,
        value=data.username,
        label=data.label,
        extra_data={},
        request=request,
    )


@router.post("/ip", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_ip_target(
    workspace_id: UUID,
    data: IPTargetCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Create IP target. Requires ANALYST role. Validates IP format."""
    return _create_target(
        db=db,
        workspace_id=workspace_id,
        user_id=user.id,
        target_type=TargetType.IP.value,
        value=data.ip,
        label=data.label,
        extra_data={},
        request=request,
    )


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    workspace_id: UUID,
    target_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """Delete target. Requires ANALYST role."""
    target = db.execute(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Audit before delete
    create_audit_log(
        db=db,
        action="target.delete",
        resource_type="target",
        resource_id=target.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"target_type": target.target_type, "value": target.value},
    )
    
    db.delete(target)
    db.commit()
