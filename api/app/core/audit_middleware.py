"""
Automatic audit logging middleware.

This middleware automatically logs all mutating requests without
requiring manual calls in each endpoint. This ensures consistent
audit coverage and prevents endpoints from "forgetting" to audit.
"""
import uuid
import time
from typing import Any
from datetime import datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse
import structlog

from app.core.security_v1 import get_audit_action


logger = structlog.get_logger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware that automatically logs auditable actions.
    
    Features:
    - Automatic detection of auditable endpoints (POST, PUT, DELETE, PATCH)
    - Request ID generation and propagation
    - Response status logging
    - Duration tracking
    - User identification from JWT
    - Workspace extraction from path
    
    This ensures audit coverage without manual intervention.
    """
    
    # Methods that should be audited
    AUDITABLE_METHODS = frozenset(["POST", "PUT", "DELETE", "PATCH"])
    
    # Paths to skip auditing
    SKIP_PATHS = frozenset([
        "/",
        "/healthz",
        "/readyz",
        "/docs",
        "/redoc",
        "/openapi.json",
    ])
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate or propagate request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        
        # Skip non-auditable paths
        if request.url.path in self.SKIP_PATHS:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        
        # Start timing
        start_time = time.perf_counter()
        
        # Extract audit context before processing
        audit_context = self._extract_audit_context(request, request_id)
        
        # Process the request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        # Add request ID to response
        response.headers["X-Request-ID"] = request_id
        
        # Log audit entry asynchronously (non-blocking)
        if self._should_audit(request, response):
            await self._log_audit_entry(
                request=request,
                response=response,
                audit_context=audit_context,
                duration_ms=duration_ms,
            )
        
        return response
    
    def _should_audit(self, request: Request, response: Response) -> bool:
        """Determine if request should be audited."""
        # Always audit mutating methods
        if request.method in self.AUDITABLE_METHODS:
            return True
        
        # Audit specific GET endpoints (exports)
        action = get_audit_action(request.method, request.url.path)
        if action and action.endswith(".export"):
            return True
        
        return False
    
    def _extract_audit_context(self, request: Request, request_id: str) -> dict[str, Any]:
        """Extract audit context from request."""
        context = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("User-Agent"),
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": None,
            "workspace_id": None,
        }
        
        # Extract user_id from JWT
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            from app.core.security import decode_access_token
            token = auth_header.split(" ")[1]
            try:
                payload = decode_access_token(token)
                if payload:
                    context["user_id"] = payload.get("sub")
            except Exception:
                pass
        
        # Extract workspace_id from path
        path_parts = request.url.path.split("/")
        for i, part in enumerate(path_parts):
            if part == "workspaces" and i + 1 < len(path_parts):
                try:
                    context["workspace_id"] = path_parts[i + 1]
                except (IndexError, ValueError):
                    pass
                break
        
        return context
    
    async def _log_audit_entry(
        self,
        request: Request,
        response: Response,
        audit_context: dict[str, Any],
        duration_ms: float,
    ) -> None:
        """
        Log audit entry to structured log and database.
        
        Uses structured logging for immediate visibility,
        and async DB write for persistence.
        """
        # Determine action
        action = get_audit_action(request.method, request.url.path)
        if not action:
            # Fallback action
            action = f"{request.method.lower()}:{request.url.path}"
        
        # Determine success
        is_success = 200 <= response.status_code < 400
        
        # Build log entry (no 'event' key - structlog uses first arg as event)
        log_entry = {
            "audit_type": "request",
            "action": action,
            "success": is_success,
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 2),
            **audit_context,
        }
        
        # Log using structlog (first arg is event name, rest are kwargs)
        if is_success:
            logger.info("audit.action", **log_entry)
        else:
            logger.warning("audit.action.failed", **log_entry)
        
        # Async DB write (non-blocking)
        # Note: In production, this could be sent to a queue
        try:
            await self._persist_audit_log(log_entry, action, is_success, response.status_code)
        except Exception as e:
            logger.error("audit.persist.failed", error=str(e), **audit_context)
    
    async def _persist_audit_log(
        self,
        log_entry: dict[str, Any],
        action: str,
        is_success: bool,
        status_code: int,
    ) -> None:
        """
        Persist audit log to database.
        
        This is async to not block the response.
        """
        from app.db.session import SessionLocal
        from app.models.audit_log import AuditLog
        
        # Parse UUIDs
        user_id = None
        workspace_id = None
        
        if log_entry.get("user_id"):
            try:
                user_id = uuid.UUID(log_entry["user_id"])
            except (ValueError, TypeError):
                pass
        
        if log_entry.get("workspace_id"):
            try:
                workspace_id = uuid.UUID(log_entry["workspace_id"])
            except (ValueError, TypeError):
                pass
        
        # Create audit log entry
        db = SessionLocal()
        try:
            audit = AuditLog(
                workspace_id=workspace_id,
                actor_user_id=user_id,
                action=action,
                resource_type=action.split(".")[0] if "." in action else "api",
                ip=log_entry.get("ip"),
                user_agent=log_entry.get("user_agent"),
                request_id=log_entry.get("request_id"),
                details_json={
                    "method": log_entry.get("method"),
                    "path": log_entry.get("path"),
                    "status_code": status_code,
                    "success": is_success,
                    "duration_ms": log_entry.get("duration_ms"),
                },
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error("audit.db.failed", error=str(e))
        finally:
            db.close()

