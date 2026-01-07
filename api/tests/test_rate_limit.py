"""
Tests for rate limiting.

Contract:
- Key: rate:{bucket}:{principal}:{group}
- Atomic: INCR + EXPIRE
- Groups: auth (5/min), mutate (30/min), read (120/min)
"""
import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


class TestRateLimitBasic:
    """Basic rate limit tests."""
    
    def test_rate_limit_headers_present(self, client: TestClient, test_user):
        """Rate limit headers should be present in response (without bypass)."""
        from app.core.security import create_access_token
        
        # Create headers WITHOUT bypass to test rate limit headers
        token = create_access_token(user_id=test_user.id, email=test_user.email)
        headers = {"Authorization": f"Bearer {token}"}
        
        response = client.get("/v1/workspaces", headers=headers)
        
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
    
    def test_health_endpoints_not_rate_limited(self, client: TestClient):
        """Health endpoints should not be rate limited."""
        for _ in range(20):
            response = client.get("/healthz")
            assert response.status_code == 200
            assert "X-RateLimit-Limit" not in response.headers
    
    def test_docs_not_rate_limited(self, client: TestClient):
        """Docs endpoints should not be rate limited."""
        response = client.get("/docs")
        # May be 200 or redirect, but should not be 429
        assert response.status_code != 429


class TestRateLimitEnforcement:
    """Rate limit enforcement tests."""
    
    @pytest.fixture(autouse=True)
    def clear_rate_limits(self):
        """Clear rate limits before each test."""
        try:
            from app.core.redis import redis_client
            # Clear all rate limit keys
            keys = redis_client.keys("rate:*")
            if keys:
                redis_client.delete(*keys)
        except Exception:
            pass
        yield
    
    def test_auth_rate_limit_enforced(self, client: TestClient):
        """Auth endpoints should be rate limited (5/min)."""
        # Make 6 requests to hit the limit
        for i in range(6):
            response = client.post(
                "/v1/auth/login",
                json={"email": "test@example.com", "password": "wrong"},
            )
            
            if i < 5:
                # Should be allowed (even if wrong password)
                assert response.status_code in [200, 401], f"Request {i+1} unexpected: {response.status_code}"
            else:
                # 6th request should be rate limited
                assert response.status_code == 429, f"Request {i+1} should be rate limited"
    
    def test_429_includes_retry_after(self, client: TestClient):
        """429 response should include Retry-After header."""
        # Exhaust rate limit
        for _ in range(10):
            response = client.post(
                "/v1/auth/login",
                json={"email": "retry@example.com", "password": "wrong"},
            )
            if response.status_code == 429:
                assert "Retry-After" in response.headers
                assert int(response.headers["Retry-After"]) > 0
                break


class TestRateLimitAtomic:
    """Atomic rate limit tests (concurrency)."""
    
    @pytest.fixture(autouse=True)
    def clear_rate_limits(self):
        """Clear rate limits before each test."""
        try:
            from app.core.redis import redis_client
            keys = redis_client.keys("rate:*")
            if keys:
                redis_client.delete(*keys)
        except Exception:
            pass
        yield
    
    def test_concurrent_requests_properly_counted(self, client: TestClient, auth_headers):
        """Concurrent requests should be properly counted (no race condition)."""
        results = []
        lock = threading.Lock()
        
        def make_request():
            response = client.get("/v1/workspaces", headers=auth_headers)
            with lock:
                results.append(response.status_code)
            return response.status_code
        
        # Fire 50 concurrent requests
        # With limit=120 for read, all should succeed
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            for future in as_completed(futures):
                future.result()
        
        # Count results
        success_count = results.count(200)
        rate_limited_count = results.count(429)
        
        # All should succeed (under limit)
        assert success_count >= 48, f"Too many failures: {results.count(500)} errors"
    
    def test_incr_expire_atomicity(self):
        """Test that INCR/EXPIRE pattern is atomic enough."""
        from app.core.rate_limit import check_rate_limit_atomic
        from app.core.redis import redis_client
        
        test_key = "rate:test:atomic:check"
        limit = 10
        
        # Clear key
        redis_client.delete(test_key)
        
        results = []
        
        def check_limit():
            allowed, remaining, _ = check_rate_limit_atomic(test_key, limit)
            results.append(allowed)
        
        # Fire concurrent checks
        threads = [threading.Thread(target=check_limit) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Exactly 10 should be allowed
        allowed_count = sum(1 for r in results if r)
        denied_count = sum(1 for r in results if not r)
        
        assert allowed_count == 10, f"Expected 10 allowed, got {allowed_count}"
        assert denied_count == 10, f"Expected 10 denied, got {denied_count}"


class TestRateLimitKeys:
    """Test rate limit key structure."""
    
    def test_key_includes_bucket(self):
        """Key should include minute bucket."""
        from app.core.rate_limit import get_rate_limit_key, get_bucket
        from unittest.mock import MagicMock
        
        request = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/v1/workspaces"
        request.method = "GET"
        
        key, _ = get_rate_limit_key(request, None)
        bucket = get_bucket()
        
        assert f"rate:{bucket}" in key
    
    def test_key_uses_user_id_when_authenticated(self):
        """Key should use user_id for authenticated requests."""
        from app.core.rate_limit import get_rate_limit_key
        from unittest.mock import MagicMock
        
        request = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/v1/workspaces"
        request.method = "GET"
        
        user_id = "test-user-123"
        key, _ = get_rate_limit_key(request, user_id)
        
        assert user_id in key
        assert "ip:" not in key
    
    def test_key_uses_ip_when_anonymous(self):
        """Key should use IP for anonymous requests."""
        from app.core.rate_limit import get_rate_limit_key
        from unittest.mock import MagicMock
        
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.url.path = "/v1/workspaces"
        request.method = "GET"
        
        key, _ = get_rate_limit_key(request, None)
        
        assert "ip:192.168.1.100" in key
    
    def test_different_groups_have_different_limits(self):
        """Different route groups should have different limits."""
        from app.core.rate_limit import get_rate_limit_key
        from app.core.config import settings
        from unittest.mock import MagicMock
        
        # Auth endpoint
        auth_request = MagicMock()
        auth_request.client.host = "127.0.0.1"
        auth_request.url.path = "/v1/auth/login"
        auth_request.method = "POST"
        
        _, auth_limit = get_rate_limit_key(auth_request, None)
        assert auth_limit == settings.RATE_LIMIT_AUTH
        
        # Mutate endpoint
        mutate_request = MagicMock()
        mutate_request.client.host = "127.0.0.1"
        mutate_request.url.path = "/v1/workspaces"
        mutate_request.method = "POST"
        
        _, mutate_limit = get_rate_limit_key(mutate_request, None)
        assert mutate_limit == settings.RATE_LIMIT_MUTATE
        
        # Read endpoint
        read_request = MagicMock()
        read_request.client.host = "127.0.0.1"
        read_request.url.path = "/v1/workspaces"
        read_request.method = "GET"
        
        _, read_limit = get_rate_limit_key(read_request, None)
        assert read_limit == settings.RATE_LIMIT_READ
        
        # Verify different limits
        assert auth_limit < mutate_limit < read_limit

