"""
Tests for authentication endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4


# Header to bypass rate limiting in tests
BYPASS_HEADERS = {"X-Test-Bypass-RateLimit": "1"}


class TestAuth:
    """Auth endpoint tests."""
    
    def test_register_success(self, client: TestClient):
        """Test successful registration."""
        response = client.post(
            "/v1/auth/register",
            headers=BYPASS_HEADERS,
            json={
                "email": f"newuser-{uuid4()}@example.com",
                "password": "SecurePassword123!",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert "email" in data
        assert "id" in data
        assert "password" not in data
        assert "password_hash" not in data
    
    def test_register_weak_password(self, client: TestClient):
        """Test registration with weak password fails."""
        response = client.post(
            "/v1/auth/register",
            headers=BYPASS_HEADERS,
            json={
                "email": f"weak-{uuid4()}@example.com",
                "password": "weak",
            },
        )
        # API returns 400 (Bad Request) for weak passwords
        assert response.status_code in (400, 422)
    
    def test_register_duplicate_email(self, client: TestClient, test_user):
        """Test registration with existing email fails."""
        response = client.post(
            "/v1/auth/register",
            headers=BYPASS_HEADERS,
            json={
                "email": test_user.email,
                "password": "SecurePassword123!",
            },
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_login_success(self, client: TestClient, test_user):
        """Test successful login."""
        response = client.post(
            "/v1/auth/login",
            headers=BYPASS_HEADERS,
            json={
                "email": test_user.email,
                "password": "TestPassword123!",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_wrong_password(self, client: TestClient, test_user):
        """Test login with wrong password fails."""
        response = client.post(
            "/v1/auth/login",
            headers=BYPASS_HEADERS,
            json={
                "email": test_user.email,
                "password": "WrongPassword123!",
            },
        )
        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()
    
    def test_login_nonexistent_user(self, client: TestClient):
        """Test login with non-existent user fails."""
        response = client.post(
            "/v1/auth/login",
            headers=BYPASS_HEADERS,
            json={
                "email": "nonexistent@example.com",
                "password": "SomePassword123!",
            },
        )
        assert response.status_code == 401
    
    def test_me_authenticated(self, client: TestClient, test_user, auth_headers):
        """Test /me endpoint with valid token."""
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
    
    def test_me_no_token(self, client: TestClient):
        """Test /me endpoint without token fails."""
        response = client.get("/v1/auth/me", headers=BYPASS_HEADERS)
        # Can be 401 (Unauthorized) or 403 (Forbidden) depending on auth flow
        assert response.status_code in (401, 403)
    
    def test_me_invalid_token(self, client: TestClient):
        """Test /me endpoint with invalid token fails."""
        headers = {**BYPASS_HEADERS, "Authorization": "Bearer invalid-token"}
        response = client.get("/v1/auth/me", headers=headers)
        assert response.status_code == 401
