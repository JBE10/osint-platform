"""Workspace management endpoints."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_viewer, require_admin, require_owner
from app.core.audit import create_audit_log
from app.models.workspace import Workspace, WorkspaceMember

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


class WorkspaceCreate(BaseModel):
    name: str


class WorkspaceResponse(BaseModel):
    id: UUID
    name: str

    class Config:
        from_attributes = True


class MemberResponse(BaseModel):
    workspace_id: UUID
    user_id: UUID
    role: str

    class Config:
        from_attributes = True


@router.post("", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
def create_workspace(
    data: WorkspaceCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    """Create a new workspace. User becomes OWNER."""
    workspace = Workspace(name=data.name)
    db.add(workspace)
    db.flush()

    # Add creator as OWNER
    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=user.id,
        role="OWNER",
    )
    db.add(member)
    db.commit()
    db.refresh(workspace)

    # Audit
    create_audit_log(
        db=db,
        action="workspace.create",
        resource_type="workspace",
        resource_id=workspace.id,
        workspace_id=workspace.id,
        actor_user_id=user.id,
        request=request,
        details={"name": data.name},
    )

    return workspace


@router.get("", response_model=list[WorkspaceResponse])
def list_workspaces(
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    """List workspaces the user is a member of."""
    memberships = db.execute(
        select(WorkspaceMember).where(WorkspaceMember.user_id == user.id)
    ).scalars().all()

    workspace_ids = [m.workspace_id for m in memberships]
    workspaces = db.execute(
        select(Workspace).where(Workspace.id.in_(workspace_ids))
    ).scalars().all()

    return workspaces


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
def get_workspace(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get workspace details. Requires VIEWER role or higher."""
    workspace = db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    ).scalar_one_or_none()

    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    return workspace


@router.get("/{workspace_id}/members", response_model=list[MemberResponse])
def list_members(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """List workspace members. Requires VIEWER role."""
    members = db.execute(
        select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id)
    ).scalars().all()

    return members


@router.post("/{workspace_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
def add_member(
    workspace_id: UUID,
    user_id: UUID,
    role: str,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[WorkspaceMember, Depends(require_admin)],
):
    """Add a member to workspace. Requires ADMIN role."""
    if role not in ("ADMIN", "ANALYST", "VIEWER"):
        raise HTTPException(status_code=400, detail="Invalid role")

    member = WorkspaceMember(
        workspace_id=workspace_id,
        user_id=user_id,
        role=role,
    )
    db.add(member)
    db.commit()
    db.refresh(member)

    # Audit
    create_audit_log(
        db=db,
        action="workspace.member_add",
        resource_type="workspace_member",
        resource_id=user_id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"added_user_id": str(user_id), "role": role},
    )

    return member

