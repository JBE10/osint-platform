from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.core.audit import audit_login, create_audit_log
from app.core.validators import OSINTEmail
from app.core.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: OSINTEmail
    password: str


class LoginRequest(BaseModel):
    email: OSINTEmail
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: UUID
    email: str
    is_active: bool

    class Config:
        from_attributes = True


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    data: RegisterRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """Register a new user."""
    # Check if email already exists
    existing = db.execute(select(User).where(User.email == data.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    # Validate password strength (basic)
    if len(data.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )
    
    # Create user
    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Audit
    create_audit_log(
        db=db,
        action="auth.register",
        resource_type="user",
        resource_id=user.id,
        actor_user_id=user.id,
        request=request,
    )
    
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    data: LoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """Login and get access token."""
    user = db.execute(select(User).where(User.email == data.email)).scalar_one_or_none()
    
    if user is None or not verify_password(data.password, user.password_hash):
        # Audit failed login attempt
        if user:
            audit_login(db, user.id, request, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated",
        )
    
    # Get user's workspace IDs
    workspace_ids = [str(m.workspace_id) for m in user.workspace_memberships]
    
    # Create token
    token = create_access_token(
        user_id=user.id,
        email=user.email,
        workspace_ids=workspace_ids,
    )
    
    # Audit successful login
    audit_login(db, user.id, request, success=True)
    
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
def get_me(
    user: Annotated[User, Depends(get_current_user)],
):
    """Get current user info."""
    return user
