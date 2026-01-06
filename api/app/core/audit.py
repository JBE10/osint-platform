import uuid
from typing import Any
from fastapi import Request
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Create an audit log entry.
    
    Actions:
        - auth.login, auth.logout, auth.register
        - target.create, target.update, target.delete
        - job.create, job.run, job.cancel
        - workspace.create, workspace.update, workspace.member_add, workspace.member_remove
        - data.export
    """
    ip = None
    user_agent = None
    request_id = None
    
    if request:
        ip = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")
        request_id = request.headers.get("X-Request-ID")
    
    # Sanitize details - remove sensitive data
    safe_details = None
    if details:
        safe_details = {
            k: v for k, v in details.items()
            if k not in ("password", "password_hash", "token", "secret", "api_key")
        }
    
    log = AuditLog(
        workspace_id=workspace_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
        details_json=safe_details,
    )
    
    db.add(log)
    db.commit()
    db.refresh(log)
    
    return log


# Convenience functions for common audit actions
def audit_login(db: Session, user_id: uuid.UUID, request: Request, success: bool = True):
    return create_audit_log(
        db=db,
        action="auth.login",
        resource_type="user",
        resource_id=user_id,
        actor_user_id=user_id if success else None,
        request=request,
        details={"success": success},
    )


def audit_target_create(
    db: Session,
    target_id: uuid.UUID,
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    target_type: str,
):
    return create_audit_log(
        db=db,
        action="target.create",
        resource_type="target",
        resource_id=target_id,
        workspace_id=workspace_id,
        actor_user_id=user_id,
        request=request,
        details={"target_type": target_type},
    )


def audit_job_run(
    db: Session,
    job_id: uuid.UUID,
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    job_type: str,
):
    return create_audit_log(
        db=db,
        action="job.run",
        resource_type="job",
        resource_id=job_id,
        workspace_id=workspace_id,
        actor_user_id=user_id,
        request=request,
        details={"job_type": job_type},
    )

