import time
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.redis import redis_client
from app.core.config import settings


def get_rate_limit_key(request: Request, user_id: str | None) -> tuple[str, int]:
    """
    Get rate limit key and limit based on request.
    Returns (key, limit_per_minute).
    """
    path = request.url.path
    ip = request.client.host if request.client else "unknown"
    
    # Determine endpoint group and limit
    if path.startswith("/auth"):
        group = "auth"
        limit = settings.RATE_LIMIT_AUTH
    elif request.method in ("POST", "PUT", "DELETE", "PATCH"):
        group = "mutate"
        limit = settings.RATE_LIMIT_MUTATE
    else:
        group = "read"
        limit = settings.RATE_LIMIT_READ
    
    # Build key: prefer user_id, fallback to IP
    if user_id:
        key = f"rate:{user_id}:{group}"
    else:
        key = f"rate:ip:{ip}:{group}"
    
    return key, limit


def check_rate_limit(key: str, limit: int, window: int = 60) -> tuple[bool, int, int]:
    """
    Check rate limit using Redis sliding window.
    Returns (allowed, remaining, retry_after).
    """
    try:
        current = redis_client.get(key)
        
        if current is None:
            redis_client.setex(key, window, 1)
            return True, limit - 1, 0
        
        count = int(current)
        if count >= limit:
            ttl = redis_client.ttl(key)
            return False, 0, ttl if ttl > 0 else window
        
        redis_client.incr(key)
        return True, limit - count - 1, 0
        
    except Exception:
        # If Redis fails, allow the request
        return True, limit, 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip health endpoints
        if request.url.path in ("/healthz", "/readyz", "/", "/docs", "/openapi.json"):
            return await call_next(request)
        
        # Try to get user_id from token (if present)
        user_id = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            from app.core.security import decode_access_token
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            if payload:
                user_id = payload.get("sub")
        
        key, limit = get_rate_limit_key(request, user_id)
        allowed, remaining, retry_after = check_rate_limit(key, limit)
        
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(retry_after)},
            )
        
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response
