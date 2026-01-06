"""Celery client for sending jobs from API to worker."""
import os
from celery import Celery

from app.models.job import Job

# Celery configuration
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/1")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/2")

# Create Celery app (client mode - no tasks defined here)
celery_app = Celery(
    "osint_api_client",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)


def send_job_to_celery(job: Job) -> str:
    """
    Send a job to the Celery worker.
    
    Returns the Celery task ID.
    """
    # Map job types to Celery task names
    task_name = f"worker_app.tasks.{job.job_type}"
    
    # Send task
    result = celery_app.send_task(
        task_name,
        kwargs={
            "job_id": str(job.id),
            "workspace_id": str(job.workspace_id),
            "target_id": str(job.target_id),
            "config": job.config,
        },
        queue="default",
    )
    
    return result.id

