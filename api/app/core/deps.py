from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.models.workspace import WorkspaceMember

security = HTTPBearer()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Get current authenticated user from JWT token."""
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    
    user = db.execute(select(User).where(User.id == UUID(user_id))).scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


class RoleChecker:
    """Dependency to check user role in workspace."""
    
    ROLE_HIERARCHY = {"OWNER": 4, "ADMIN": 3, "ANALYST": 2, "VIEWER": 1}
    
    def __init__(self, min_role: str):
        self.min_role = min_role
        self.min_level = self.ROLE_HIERARCHY.get(min_role, 0)
    
    def __call__(
        self,
        workspace_id: UUID,
        user: CurrentUser,
        db: Annotated[Session, Depends(get_db)],
    ) -> WorkspaceMember:
        """Check if user has required role in workspace."""
        membership = db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == user.id,
            )
        ).scalar_one_or_none()
        
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this workspace",
            )
        
        user_level = self.ROLE_HIERARCHY.get(membership.role, 0)
        if user_level < self.min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {self.min_role} role or higher",
            )
        
        return membership


# Pre-configured role checkers
require_viewer = RoleChecker("VIEWER")
require_analyst = RoleChecker("ANALYST")
require_admin = RoleChecker("ADMIN")
require_owner = RoleChecker("OWNER")

