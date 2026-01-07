"""
Atomic rate limiting using Redis INCR/EXPIRE.

Contract:
- Key: rate:{bucket}:{principal}:{route_group}
- Bucket: minute timestamp (floor to minute)
- Principal: user_id or IP
- Route group: auth | read | mutate

Operation (atomic per Redis):
1. count = INCR key
2. if count == 1 then EXPIRE key 60
3. if count > limit → 429

This eliminates race conditions without Lua complexity.
"""
import time
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.redis import redis_client
from app.core.config import settings


def get_bucket() -> int:
    """Get current minute bucket (epoch // 60)."""
    return int(time.time()) // 60


def get_rate_limit_key(request: Request, user_id: str | None) -> tuple[str, int]:
    """
    Build rate limit key and get limit.
    
    Key format: rate:{bucket}:{principal}:{group}
    
    Returns (key, limit_per_minute).
    """
    bucket = get_bucket()
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    # Determine route group and limit
    if "/auth" in path:
        group = "auth"
        limit = settings.RATE_LIMIT_AUTH
    elif request.method in ("POST", "PUT", "DELETE", "PATCH"):
        group = "mutate"
        limit = settings.RATE_LIMIT_MUTATE
    else:
        group = "read"
        limit = settings.RATE_LIMIT_READ
    
    # Principal: prefer user_id, fallback to IP
    principal = user_id if user_id else f"ip:{ip}"
    
    key = f"rate:{bucket}:{principal}:{group}"
    return key, limit


def check_rate_limit_atomic(key: str, limit: int, window: int = 60) -> tuple[bool, int, int]:
    """
    Check rate limit using atomic INCR/EXPIRE.
    
    Returns (allowed, remaining, retry_after_seconds).
    
    Contract:
    1. count = INCR key (atomic)
    2. if count == 1 → EXPIRE key window (first request in window)
    3. if count > limit → denied
    """
    try:
        # INCR is atomic - returns value after increment
        count = redis_client.incr(key)
        
        # First request in this window - set expiry
        if count == 1:
            redis_client.expire(key, window)
        
        # Check limit
        if count > limit:
            ttl = redis_client.ttl(key)
            retry_after = ttl if ttl > 0 else window
            return False, 0, retry_after
        
        remaining = limit - count
        return True, remaining, 0
        
    except Exception:
        # If Redis fails, allow the request (fail open)
        return True, limit, 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using atomic Redis INCR/EXPIRE.
    
    Features:
    - Atomic counter (no race conditions)
    - Per-user limits for authenticated requests
    - Per-IP limits for anonymous requests
    - Different limits: auth (5/min) < mutate (30/min) < read (120/min)
    - Standard headers: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After
    - Test bypass via X-Test-Bypass-RateLimit header (only in local/test env)
    """
    
    # Paths to skip rate limiting
    SKIP_PATHS = frozenset([
        "/",
        "/v1",
        "/healthz",
        "/readyz",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/metrics",
    ])
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip health and docs endpoints
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)
        
        # Allow bypass in test/local environment
        if settings.ENV in ("local", "test") and request.headers.get("X-Test-Bypass-RateLimit"):
            return await call_next(request)
        
        # Extract user_id from JWT (if authenticated)
        user_id = self._extract_user_id(request)
        
        # Check rate limit
        key, limit = get_rate_limit_key(request, user_id)
        allowed, remaining, retry_after = check_rate_limit_atomic(key, limit)
        
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        
        return response
    
    def _extract_user_id(self, request: Request) -> str | None:
        """Extract user_id from JWT token if present."""
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        try:
            from app.core.security import decode_access_token
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            return payload.get("sub") if payload else None
        except Exception:
            return None
