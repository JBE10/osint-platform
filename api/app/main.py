from fastapi import FastAPI
from app.routers.health import router as health_router
from app.routers.auth import router as auth_router
from app.routers.workspaces import router as workspaces_router
from app.routers.targets import router as targets_router
from app.routers.jobs import router as jobs_router
from app.core.logging import setup_logging
from app.core.rate_limit import RateLimitMiddleware

setup_logging()

app = FastAPI(title="OSINT Platform V1", version="0.1.0")

# Middleware
app.add_middleware(RateLimitMiddleware)

# Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(workspaces_router)
app.include_router(targets_router)
app.include_router(jobs_router)


@app.get("/")
def root():
    return {"name": "osint-platform", "version": "0.1.0"}
