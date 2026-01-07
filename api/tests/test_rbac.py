"""
Tests for RBAC (Role-Based Access Control).

Roles:
- OWNER: Full access
- ADMIN: Full access except delete workspace
- ANALYST: Create/run jobs, create targets
- VIEWER: Read-only access
"""
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4


class TestRBAC:
    """RBAC enforcement tests."""
    
    # =========================================================================
    # VIEWER restrictions
    # =========================================================================
    
    def test_viewer_cannot_create_target(
        self, client: TestClient, test_workspace, viewer_user
    ):
        """VIEWER cannot create targets."""
        _, headers = viewer_user
        
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/targets/domain",
            headers=headers,
            json={"domain": "example.com"},
        )
        assert response.status_code == 403
        # Check for role-related message
        detail = response.json()["detail"].lower()
        assert "analyst" in detail or "permission" in detail
    
    def test_viewer_cannot_create_job(
        self, client: TestClient, test_workspace, viewer_user
    ):
        """VIEWER cannot create jobs."""
        _, headers = viewer_user
        
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=headers,
            json={
                "target_id": str(uuid4()),
                "technique_code": "domain_dns_lookup",
            },
        )
        assert response.status_code == 403
    
    def test_viewer_can_list_jobs(
        self, client: TestClient, test_workspace, viewer_user
    ):
        """VIEWER can list jobs (read-only)."""
        _, headers = viewer_user
        
        response = client.get(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=headers,
        )
        assert response.status_code == 200
    
    def test_viewer_can_list_findings(
        self, client: TestClient, test_workspace, viewer_user
    ):
        """VIEWER can list findings (read-only)."""
        _, headers = viewer_user
        
        response = client.get(
            f"/v1/workspaces/{test_workspace.id}/findings",
            headers=headers,
        )
        assert response.status_code == 200
    
    # =========================================================================
    # ANALYST permissions
    # =========================================================================
    
    def test_analyst_can_create_target(
        self, client: TestClient, test_workspace, analyst_user
    ):
        """ANALYST can create targets."""
        _, headers = analyst_user
        
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/targets/domain",
            headers=headers,
            json={"domain": f"analyst-test-{uuid4()}.com"},
        )
        assert response.status_code == 201
    
    def test_analyst_can_create_job(
        self, client: TestClient, db, test_workspace, analyst_user
    ):
        """ANALYST can create jobs."""
        from app.models.target import Target, TargetType
        
        user, headers = analyst_user
        
        # Create a target first
        target = Target(
            id=uuid4(),
            workspace_id=test_workspace.id,
            created_by=user.id,
            target_type=TargetType.DOMAIN.value,
            value="analyst-job-test.com",
        )
        db.add(target)
        db.commit()
        
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=headers,
            json={
                "target_id": str(target.id),
                "technique_code": "domain_dns_lookup",
            },
        )
        assert response.status_code == 201
    
    # =========================================================================
    # Cross-workspace isolation
    # =========================================================================
    
    def test_user_cannot_access_other_workspace(
        self, client: TestClient, db, test_user, auth_headers
    ):
        """User cannot access workspace they're not a member of."""
        from app.models.workspace import Workspace, WorkspaceMember
        from app.models.user import User
        from app.core.security import hash_password
        
        # Create another user with their own workspace
        other_user = User(
            id=uuid4(),
            email=f"other-{uuid4()}@example.com",
            password_hash=hash_password("OtherPassword123!"),
            is_active=True,
        )
        db.add(other_user)
        db.flush()
        
        other_workspace = Workspace(
            id=uuid4(),
            name="Other Workspace",
        )
        db.add(other_workspace)
        db.flush()
        
        # Add other_user as OWNER of the workspace
        member = WorkspaceMember(
            workspace_id=other_workspace.id,
            user_id=other_user.id,
            role="OWNER",
        )
        db.add(member)
        db.commit()
        
        # Try to access other workspace with test_user's token
        response = client.get(
            f"/v1/workspaces/{other_workspace.id}/jobs",
            headers=auth_headers,
        )
        assert response.status_code == 403
    
    # =========================================================================
    # Anonymous access
    # =========================================================================
    
    def test_anonymous_cannot_access_workspaces(self, client: TestClient):
        """Anonymous user cannot access protected endpoints."""
        response = client.get(
            "/v1/workspaces",
            headers={"X-Test-Bypass-RateLimit": "1"},
        )
        # Can be 401 (Unauthorized) or 403 (Forbidden) depending on auth flow
        assert response.status_code in (401, 403)
    
    def test_anonymous_can_access_health(self, client: TestClient):
        """Anonymous user can access health endpoints."""
        response = client.get("/healthz")
        assert response.status_code == 200

