"""
OSINT Platform V1 - Main Application.

Security hardening:
- API versioning with /v1/ prefix
- Atomic rate limiting (INCR/EXPIRE)
- Automatic audit middleware
- Config-driven technique allowlist
- Fail-fast on dangerous defaults in production
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.health import router as health_router
from app.routers.auth import router as auth_router
from app.routers.workspaces import router as workspaces_router
from app.routers.targets import router as targets_router
from app.routers.jobs import router as jobs_router
from app.routers.findings import router as findings_router
from app.routers.evidence import router as evidence_router
from app.routers.investigations import router as investigations_router
from app.core.logging import setup_logging
from app.core.rate_limit import RateLimitMiddleware
from app.core.audit_middleware import AuditMiddleware
from app.core.config import check_production_safety, settings

setup_logging()

# =============================================================================
# Production Safety Check (fail fast if misconfigured)
# =============================================================================
check_production_safety()

# =============================================================================
# Application Setup
# =============================================================================
app = FastAPI(
    title="OSINT Platform",
    description="Open Source Intelligence Platform V1",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# =============================================================================
# Middleware (order matters: first added = last executed)
# =============================================================================
# 1. Audit middleware (logs all auditable actions)
app.add_middleware(AuditMiddleware)

# 2. Rate limiting (atomic INCR/EXPIRE)
app.add_middleware(RateLimitMiddleware)

# 3. CORS (if needed for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Health/Metrics endpoints (no version prefix - for k8s probes)
# =============================================================================
app.include_router(health_router)

# =============================================================================
# API V1 Routes (with /v1 prefix)
# =============================================================================
V1_PREFIX = "/v1"

# All V1 routes
app.include_router(auth_router, prefix=V1_PREFIX)
app.include_router(workspaces_router, prefix=V1_PREFIX)
app.include_router(targets_router, prefix=V1_PREFIX)
app.include_router(jobs_router, prefix=V1_PREFIX)
app.include_router(findings_router, prefix=V1_PREFIX)
app.include_router(evidence_router, prefix=V1_PREFIX)
app.include_router(investigations_router, prefix=V1_PREFIX)


# =============================================================================
# Root endpoints
# =============================================================================
@app.get("/", tags=["root"])
def root():
    """API root - returns version info."""
    return {
        "name": "osint-platform",
        "version": "1.0.0",
        "api": "/v1",
        "docs": "/docs",
        "health": "/healthz",
    }


@app.get("/v1", tags=["root"])
def api_v1_root():
    """API V1 root - returns available endpoints and enabled techniques."""
    return {
        "version": "v1",
        "status": "stable",
        "env": settings.ENV,
        "endpoints": {
            "auth": "/v1/auth",
            "workspaces": "/v1/workspaces",
            "targets": "/v1/workspaces/{id}/targets",
            "jobs": "/v1/workspaces/{id}/jobs",
            "findings": "/v1/workspaces/{id}/findings",
            "investigations": "/v1/workspaces/{id}/investigations",
        },
        "enabled_techniques": sorted(settings.ENABLED_TECHNIQUES),
    }
