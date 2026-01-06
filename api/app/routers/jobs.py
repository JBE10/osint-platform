"""Job management endpoints."""
from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import CurrentUser, require_analyst, require_viewer
from app.core.audit import create_audit_log
from app.models.workspace import WorkspaceMember
from app.models.target import Target
from app.models.job import Job, JobStatus, JobType, generate_idempotency_key

router = APIRouter(prefix="/workspaces/{workspace_id}/jobs", tags=["jobs"])


# =============================================================================
# Schemas
# =============================================================================

class JobCreate(BaseModel):
    """Create a new job."""
    target_id: UUID
    job_type: str
    config: dict = {}


class JobResponse(BaseModel):
    """Job response."""
    id: UUID
    workspace_id: UUID
    target_id: UUID
    job_type: str
    status: str
    config: dict
    result: Optional[dict] = None
    error_message: Optional[str] = None
    raw_evidence_path: Optional[str] = None
    retry_count: int
    max_retries: int
    created_at: datetime
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# =============================================================================
# Endpoints
# =============================================================================

@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
def create_job(
    workspace_id: UUID,
    data: JobCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Create a new job. Requires ANALYST role.
    
    Uses idempotency_key to prevent duplicate jobs for same target+type+config.
    """
    # Validate job type
    try:
        JobType(data.job_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid job_type. Valid types: {[t.value for t in JobType]}",
        )
    
    # Verify target exists and belongs to workspace
    target = db.execute(
        select(Target).where(
            Target.id == data.target_id,
            Target.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Generate idempotency key
    idempotency_key = generate_idempotency_key(
        workspace_id=workspace_id,
        target_id=data.target_id,
        job_type=data.job_type,
        config=data.config,
    )
    
    # Check for existing job with same idempotency key
    existing = db.execute(
        select(Job).where(Job.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    
    if existing:
        # Return existing job (idempotent)
        return existing
    
    # Create new job
    job = Job(
        workspace_id=workspace_id,
        target_id=data.target_id,
        created_by=user.id,
        job_type=data.job_type,
        config=data.config,
        idempotency_key=idempotency_key,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Audit
    create_audit_log(
        db=db,
        action="job.create",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"job_type": data.job_type, "target_id": str(data.target_id)},
    )
    
    return job


@router.get("", response_model=list[JobResponse])
def list_jobs(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    status_filter: Optional[str] = Query(None, alias="status"),
    target_id: Optional[UUID] = None,
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    """List jobs in workspace. Requires VIEWER role."""
    query = select(Job).where(Job.workspace_id == workspace_id)
    
    if status_filter:
        query = query.where(Job.status == status_filter)
    if target_id:
        query = query.where(Job.target_id == target_id)
    
    query = query.order_by(Job.created_at.desc()).limit(limit).offset(offset)
    
    jobs = db.execute(query).scalars().all()
    return jobs


@router.get("/{job_id}", response_model=JobResponse)
def get_job(
    workspace_id: UUID,
    job_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get job details. Requires VIEWER role."""
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job


@router.post("/{job_id}/enqueue", response_model=JobResponse)
def enqueue_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Enqueue a PENDING job to Celery. Requires ANALYST role.
    """
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job.can_transition_to(JobStatus.QUEUED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot enqueue job in {job.status} state",
        )
    
    # Send to Celery
    from app.core.celery_client import send_job_to_celery
    celery_task_id = send_job_to_celery(job)
    
    # Update job
    job.transition_to(JobStatus.QUEUED)
    job.celery_task_id = celery_task_id
    db.commit()
    db.refresh(job)
    
    # Audit
    create_audit_log(
        db=db,
        action="job.enqueue",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"celery_task_id": celery_task_id},
    )
    
    return job


@router.post("/{job_id}/retry", response_model=JobResponse)
def retry_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Retry a FAILED job. Requires ANALYST role.
    """
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job.can_retry:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot retry job (status={job.status}, retries={job.retry_count}/{job.max_retries})",
        )
    
    # Increment retry count and re-enqueue
    job.retry_count += 1
    job.error_message = None
    
    from app.core.celery_client import send_job_to_celery
    celery_task_id = send_job_to_celery(job)
    
    job.transition_to(JobStatus.QUEUED)
    job.celery_task_id = celery_task_id
    db.commit()
    db.refresh(job)
    
    # Audit
    create_audit_log(
        db=db,
        action="job.retry",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"retry_count": job.retry_count},
    )
    
    return job


@router.post("/{job_id}/cancel", response_model=JobResponse)
def cancel_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Cancel a PENDING or QUEUED job. Requires ANALYST role.
    """
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job.can_transition_to(JobStatus.CANCELLED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel job in {job.status} state",
        )
    
    job.transition_to(JobStatus.CANCELLED)
    db.commit()
    db.refresh(job)
    
    # Audit
    create_audit_log(
        db=db,
        action="job.cancel",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
    )
    
    return job

