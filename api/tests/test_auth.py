"""
Tests for authentication endpoints.
"""
import pytest
from fastapi.testclient import TestClient


class TestAuth:
    """Auth endpoint tests."""
    
    def test_register_success(self, client: TestClient):
        """Test successful registration."""
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePassword123!",
                "name": "New User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert "id" in data
        assert "password" not in data
        assert "password_hash" not in data
    
    def test_register_weak_password(self, client: TestClient):
        """Test registration with weak password fails."""
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "weak@example.com",
                "password": "weak",
                "name": "Weak User",
            },
        )
        assert response.status_code == 422  # Validation error
    
    def test_register_duplicate_email(self, client: TestClient, test_user):
        """Test registration with existing email fails."""
        response = client.post(
            "/v1/auth/register",
            json={
                "email": test_user.email,
                "password": "SecurePassword123!",
                "name": "Duplicate User",
            },
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_login_success(self, client: TestClient, test_user):
        """Test successful login."""
        response = client.post(
            "/v1/auth/login",
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
        response = client.get("/v1/auth/me")
        assert response.status_code == 401
    
    def test_me_invalid_token(self, client: TestClient):
        """Test /me endpoint with invalid token fails."""
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401

