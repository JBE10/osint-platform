"""
Pytest fixtures for API tests.
"""
import os
import pytest
from typing import Generator
from uuid import uuid4

# Set test environment BEFORE importing app
os.environ.setdefault("ENV", "local")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://osint:osint@localhost:5432/osint")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-32chars")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMember
from app.core.security import hash_password, create_access_token


# =============================================================================
# Database Setup
# =============================================================================

TEST_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://osint:osint@localhost:5432/osint")

engine = create_engine(TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db() -> Generator[Session, None, None]:
    """Override database dependency for tests."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create tables once per test session."""
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db() -> Generator[Session, None, None]:
    """Get database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client() -> TestClient:
    """Get test client."""
    return TestClient(app)


@pytest.fixture
def test_user(db: Session) -> User:
    """Create a test user."""
    user = User(
        id=uuid4(),
        email=f"test-{uuid4()}@example.com",
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_workspace(db: Session, test_user: User) -> Workspace:
    """Create a test workspace with owner."""
    workspace = Workspace(
        id=uuid4(),
        name=f"Test Workspace {uuid4()}",
    )
    db.add(workspace)
    db.flush()
    
    # Add test_user as OWNER
    member = WorkspaceMember(
        workspace_id=workspace.id,
        user_id=test_user.id,
        role="OWNER",
    )
    db.add(member)
    db.commit()
    db.refresh(workspace)
    return workspace


@pytest.fixture
def auth_headers(test_user: User) -> dict:
    """Get auth headers for test user."""
    token = create_access_token(user_id=test_user.id, email=test_user.email)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_user(db: Session, test_workspace: Workspace) -> tuple[User, dict]:
    """Create a VIEWER user for RBAC tests."""
    user = User(
        id=uuid4(),
        email=f"viewer-{uuid4()}@example.com",
        password_hash=hash_password("ViewerPassword123!"),
        is_active=True,
    )
    db.add(user)
    db.flush()
    
    # Add as VIEWER
    member = WorkspaceMember(
        workspace_id=test_workspace.id,
        user_id=user.id,
        role="VIEWER",
    )
    db.add(member)
    db.commit()
    
    token = create_access_token(user_id=user.id, email=user.email)
    headers = {"Authorization": f"Bearer {token}"}
    
    return user, headers


@pytest.fixture
def analyst_user(db: Session, test_workspace: Workspace) -> tuple[User, dict]:
    """Create an ANALYST user."""
    user = User(
        id=uuid4(),
        email=f"analyst-{uuid4()}@example.com",
        password_hash=hash_password("AnalystPassword123!"),
        is_active=True,
    )
    db.add(user)
    db.flush()
    
    # Add as ANALYST
    member = WorkspaceMember(
        workspace_id=test_workspace.id,
        user_id=user.id,
        role="ANALYST",
    )
    db.add(member)
    db.commit()
    
    token = create_access_token(user_id=user.id, email=user.email)
    headers = {"Authorization": f"Bearer {token}"}
    
    return user, headers
