"""Job management endpoints - Full state machine flow."""
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
from app.core.metrics import jobs_created, jobs_enqueued
from app.models.workspace import WorkspaceMember
from app.models.target import Target
from app.models.job import Job, JobStatus, TechniqueCode, generate_idempotency_key
from app.models.finding import Finding

router = APIRouter(tags=["jobs"])


# =============================================================================
# Schemas
# =============================================================================

class JobCreate(BaseModel):
    """Create a new job."""
    target_id: UUID
    technique_code: str
    params: dict = {}
    priority: int = 5  # 1=highest, 10=lowest
    max_attempts: int = 3


class JobBatchCreate(BaseModel):
    """Create multiple jobs for same target with different techniques."""
    target_id: UUID
    techniques: list[str]
    params: dict = {}


class JobBatchResponse(BaseModel):
    """Batch job creation response."""
    job_ids: list[UUID]


class JobResponse(BaseModel):
    """Job response."""
    id: UUID
    workspace_id: UUID
    investigation_id: Optional[UUID] = None
    target_id: UUID
    technique_code: str
    status: str
    priority: int
    attempt: int
    max_attempts: int
    params_json: dict
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    trace_id: Optional[str] = None
    celery_task_id: Optional[str] = None
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    """Finding response."""
    id: UUID
    job_id: UUID
    finding_type: str
    subject: str
    confidence: int
    data_json: dict
    first_seen_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# V1 Endpoints (with investigation_id support)
# =============================================================================

@router.post(
    "/v1/workspaces/{workspace_id}/investigations/{investigation_id}/jobs",
    response_model=JobBatchResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["jobs-v1"],
)
def create_jobs_batch(
    workspace_id: UUID,
    investigation_id: UUID,
    data: JobBatchCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Create multiple jobs for a target. Requires ANALYST role.
    
    Request:
    ```json
    {
      "target_id": "uuid",
      "techniques": ["dns_lookup", "whois_lookup"],
      "params": {}
    }
    ```
    
    Response:
    ```json
    {
      "job_ids": ["uuid1", "uuid2"]
    }
    ```
    """
    # Verify target exists and belongs to workspace
    target = db.execute(
        select(Target).where(
            Target.id == data.target_id,
            Target.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    job_ids = []
    
    for technique in data.techniques:
        # Validate technique code
        try:
            TechniqueCode(technique)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid technique: {technique}. Valid: {[t.value for t in TechniqueCode]}",
            )
        
        # Generate idempotency key
        idempotency_key = generate_idempotency_key(
            workspace_id=workspace_id,
            target_id=data.target_id,
            technique_code=technique,
            params=data.params,
        )
        
        # Check for existing job
        existing = db.execute(
            select(Job).where(Job.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        
        if existing:
            job_ids.append(existing.id)
            continue
        
        # Create new job
        job = Job(
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            target_id=data.target_id,
            technique_code=technique,
            params_json=data.params,
            idempotency_key=idempotency_key,
            status=JobStatus.CREATED.value,
        )
        db.add(job)
        db.flush()  # Get the ID
        job_ids.append(job.id)
        
        # Metric
        jobs_created.labels(workspace_id=str(workspace_id), technique=technique).inc()
    
    db.commit()
    
    # Audit
    create_audit_log(
        db=db,
        action="jobs.batch_create",
        resource_type="job",
        resource_id=None,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={
            "investigation_id": str(investigation_id),
            "target_id": str(data.target_id),
            "techniques": data.techniques,
            "job_count": len(job_ids),
        },
    )
    
    return JobBatchResponse(job_ids=job_ids)


# =============================================================================
# Standard Endpoints (workspace level)
# =============================================================================

@router.post(
    "/workspaces/{workspace_id}/jobs",
    response_model=JobResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_job(
    workspace_id: UUID,
    data: JobCreate,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
    investigation_id: Optional[UUID] = Query(None),
):
    """
    Create a new job (status=CREATED). Requires ANALYST role.
    
    Flow: POST /jobs → status=CREATED
          POST /jobs/{id}/enqueue → status=QUEUED (sent to Celery)
    
    Uses idempotency_key: sha256(workspace+target+technique+params+v1)
    If job already exists with same key → returns existing job (no duplicate).
    """
    # Validate technique code
    try:
        TechniqueCode(data.technique_code)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid technique_code. Valid: {[t.value for t in TechniqueCode]}",
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
        technique_code=data.technique_code,
        params=data.params,
    )
    
    # Check for existing job with same idempotency key
    existing = db.execute(
        select(Job).where(Job.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    
    if existing:
        # Idempotent: return existing job
        return existing
    
    # Create new job (status=CREATED)
    job = Job(
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        target_id=data.target_id,
        technique_code=data.technique_code,
        params_json=data.params,
        priority=data.priority,
        max_attempts=data.max_attempts,
        idempotency_key=idempotency_key,
        status=JobStatus.CREATED.value,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Metric
    jobs_created.labels(workspace_id=str(workspace_id), technique=data.technique_code).inc()
    
    # Audit
    create_audit_log(
        db=db,
        action="job.create",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"technique_code": data.technique_code, "target_id": str(data.target_id)},
    )
    
    return job


@router.get("/workspaces/{workspace_id}/jobs", response_model=list[JobResponse])
def list_jobs(
    workspace_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
    status_filter: Optional[str] = Query(None, alias="status"),
    target_id: Optional[UUID] = None,
    investigation_id: Optional[UUID] = None,
    technique_code: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = 0,
):
    """List jobs in workspace. Requires VIEWER role."""
    query = select(Job).where(Job.workspace_id == workspace_id)
    
    if status_filter:
        query = query.where(Job.status == status_filter)
    if target_id:
        query = query.where(Job.target_id == target_id)
    if investigation_id:
        query = query.where(Job.investigation_id == investigation_id)
    if technique_code:
        query = query.where(Job.technique_code == technique_code)
    
    query = query.order_by(Job.created_at.desc()).limit(limit).offset(offset)
    
    jobs = db.execute(query).scalars().all()
    return jobs


@router.get("/workspaces/{workspace_id}/jobs/{job_id}", response_model=JobResponse)
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


@router.get("/workspaces/{workspace_id}/jobs/{job_id}/findings", response_model=list[FindingResponse])
def get_job_findings(
    workspace_id: UUID,
    job_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_viewer)],
):
    """Get findings for a job. Requires VIEWER role."""
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    findings = db.execute(
        select(Finding).where(Finding.job_id == job_id)
    ).scalars().all()
    
    return findings


@router.post("/workspaces/{workspace_id}/jobs/{job_id}/enqueue", response_model=JobResponse)
def enqueue_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Enqueue a CREATED job to Celery → status=QUEUED. Requires ANALYST role.
    
    This is the transition: CREATED → QUEUED
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
            detail=f"Cannot enqueue job in {job.status} state. Valid: CREATED",
        )
    
    # Send to Celery
    from app.core.celery_client import send_job_to_celery
    celery_task_id = send_job_to_celery(job)
    
    # Update job: CREATED → QUEUED
    job.transition_to(JobStatus.QUEUED)
    job.celery_task_id = celery_task_id
    db.commit()
    db.refresh(job)
    
    # Metric
    jobs_enqueued.labels(workspace_id=str(workspace_id), technique=job.technique_code).inc()
    
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


@router.post("/workspaces/{workspace_id}/jobs/{job_id}/requeue", response_model=JobResponse)
def requeue_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Re-queue a FAILED or DEAD_LETTER job. Requires ANALYST role.
    
    Transitions: RETRYING → QUEUED (auto), FAILED → QUEUED (manual), DEAD_LETTER → QUEUED (manual)
    """
    job = db.execute(
        select(Job).where(
            Job.id == job_id,
            Job.workspace_id == workspace_id,
        )
    ).scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Can requeue from RETRYING, FAILED, or DEAD_LETTER
    if job.status not in (JobStatus.RETRYING.value, JobStatus.FAILED.value, JobStatus.DEAD_LETTER.value):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot requeue job in {job.status} state. Valid: RETRYING, FAILED, DEAD_LETTER",
        )
    
    # For DEAD_LETTER, reset attempts (manual intervention)
    if job.status == JobStatus.DEAD_LETTER.value:
        job.attempt = 0
    
    # Clear error
    job.error_code = None
    job.error_message = None
    job.finished_at = None
    
    # Send to Celery
    from app.core.celery_client import send_job_to_celery
    celery_task_id = send_job_to_celery(job)
    
    # Force transition to QUEUED (bypass state machine for manual intervention)
    job.status = JobStatus.QUEUED.value
    job.celery_task_id = celery_task_id
    db.commit()
    db.refresh(job)
    
    # Metric
    jobs_enqueued.labels(workspace_id=str(workspace_id), technique=job.technique_code).inc()
    
    # Audit
    create_audit_log(
        db=db,
        action="job.requeue",
        resource_type="job",
        resource_id=job.id,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        request=request,
        details={"celery_task_id": celery_task_id, "attempt": job.attempt},
    )
    
    return job


@router.post("/workspaces/{workspace_id}/jobs/{job_id}/cancel", response_model=JobResponse)
def cancel_job(
    workspace_id: UUID,
    job_id: UUID,
    request: Request,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    membership: Annotated[WorkspaceMember, Depends(require_analyst)],
):
    """
    Cancel a CREATED or QUEUED job. Requires ANALYST role.
    
    Transition: CREATED → CANCELLED, QUEUED → CANCELLED
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
            detail=f"Cannot cancel job in {job.status} state. Valid: CREATED, QUEUED",
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
