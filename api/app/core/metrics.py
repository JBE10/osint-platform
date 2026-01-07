"""Prometheus metrics for observability."""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# =============================================================================
# Job Metrics
# =============================================================================

jobs_created = Counter(
    "osint_jobs_created_total",
    "Total number of jobs created",
    ["workspace_id", "technique"],
)

jobs_enqueued = Counter(
    "osint_jobs_enqueued_total",
    "Total number of jobs enqueued to Celery",
    ["workspace_id", "technique"],
)

jobs_started = Counter(
    "osint_jobs_started_total",
    "Total number of jobs started by workers",
    ["workspace_id", "technique"],
)

jobs_succeeded = Counter(
    "osint_jobs_succeeded_total",
    "Total number of jobs completed successfully",
    ["workspace_id", "technique"],
)

jobs_failed = Counter(
    "osint_jobs_failed_total",
    "Total number of jobs that failed",
    ["workspace_id", "technique", "error_code"],
)

jobs_retrying = Counter(
    "osint_jobs_retrying_total",
    "Total number of job retries",
    ["workspace_id", "technique"],
)

jobs_dead_letter = Counter(
    "osint_jobs_dead_letter_total",
    "Total number of jobs sent to dead letter queue",
    ["workspace_id", "technique"],
)

# =============================================================================
# Job Duration Metrics
# =============================================================================

job_duration_seconds = Histogram(
    "osint_job_duration_seconds",
    "Job execution duration in seconds",
    ["workspace_id", "technique"],
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300],
)

# =============================================================================
# Evidence Metrics
# =============================================================================

evidence_stored = Counter(
    "osint_evidence_stored_total",
    "Total number of evidence files stored",
    ["workspace_id", "source"],
)

evidence_bytes = Counter(
    "osint_evidence_bytes_total",
    "Total bytes of evidence stored",
    ["workspace_id"],
)

# =============================================================================
# Finding Metrics
# =============================================================================

findings_created = Counter(
    "osint_findings_created_total",
    "Total number of findings created",
    ["workspace_id", "finding_type"],
)

findings_updated = Counter(
    "osint_findings_updated_total",
    "Total number of findings updated (deduplication)",
    ["workspace_id", "finding_type"],
)

# =============================================================================
# Active Jobs Gauge
# =============================================================================

active_jobs = Gauge(
    "osint_active_jobs",
    "Number of currently active jobs",
    ["workspace_id", "status"],
)


def get_metrics():
    """Generate Prometheus metrics output."""
    return generate_latest()


def get_metrics_content_type():
    """Get Prometheus content type."""
    return CONTENT_TYPE_LATEST

