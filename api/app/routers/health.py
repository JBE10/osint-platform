from fastapi import APIRouter, Response
from app.db.session import check_db
from app.core.redis import check_redis
from app.core.metrics import get_metrics, get_metrics_content_type

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    """Liveness probe - Is the service alive?"""
    return {"ok": True}


@router.get("/readyz")
def readyz():
    """Readiness probe - Is the service ready to accept traffic?"""
    db_ok = check_db()
    redis_ok = check_redis()
    ok = db_ok and redis_ok
    return {"ok": ok, "db": db_ok, "redis": redis_ok}


@router.get("/metrics")
def metrics():
    """
    Prometheus metrics endpoint.
    
    Exposed metrics:
    - osint_jobs_created_total
    - osint_jobs_enqueued_total
    - osint_jobs_started_total
    - osint_jobs_succeeded_total
    - osint_jobs_failed_total
    - osint_jobs_retrying_total
    - osint_jobs_dead_letter_total
    - osint_job_duration_seconds
    - osint_evidence_stored_total
    - osint_evidence_bytes_total
    - osint_findings_created_total
    - osint_findings_updated_total
    - osint_active_jobs
    """
    return Response(
        content=get_metrics(),
        media_type=get_metrics_content_type(),
    )
