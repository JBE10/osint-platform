from fastapi import APIRouter
from app.db.session import check_db
from app.core.redis import check_redis

router = APIRouter(tags=["health"])

@router.get("/healthz")
def healthz():
    return {"ok": True}

@router.get("/readyz")
def readyz():
    db_ok = check_db()
    redis_ok = check_redis()
    ok = db_ok and redis_ok
    return {"ok": ok, "db": db_ok, "redis": redis_ok}
