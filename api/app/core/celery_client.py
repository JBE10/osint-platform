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
    
    Contract: Worker receives ONLY job_id.
    Worker must rehydrate job from DB (source of truth).
    
    Returns the Celery task ID.
    """
    # Single unified task: execute_job
    # Worker rehydrates job from DB using job_id
    result = celery_app.send_task(
        "worker_app.tasks.execute_job",
        kwargs={"job_id": str(job.id)},
        queue="celery",  # Default Celery queue
        priority=job.priority,  # Celery priority (lower = higher)
    )
    
    return result.id
