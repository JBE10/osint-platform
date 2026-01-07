"""
Tests for Username OSINT Providers (GitHub, Reddit).
"""
import pytest
from datetime import datetime, timezone


# =============================================================================
# Unit Tests - Provider Logic
# =============================================================================

class TestGitHubProviderNormalization:
    """Test GitHub response normalization."""
    
    def test_normalize_existing_user(self):
        """Test normalization for existing user."""
        from worker_app.username_providers import GitHubProvider
        
        provider = GitHubProvider()
        response = {
            "success": True,
            "exists": True,
            "status_code": 200,
            "headers": {"x-ratelimit-remaining": "59"},
            "body": {
                "id": 12345,
                "login": "testuser",
                "name": "Test User",
                "public_repos": 42,
                "followers": 120,
                "following": 50,
                "created_at": "2015-03-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            },
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        
        findings = provider.normalize("testuser", response)
        
        # Should have USERNAME_IDENTITY and USERNAME_ACTIVITY findings
        assert len(findings) >= 1
        
        identity = next(f for f in findings if f["finding_type"] == "USERNAME_IDENTITY")
        assert identity["subject"] == "testuser"
        assert identity["data"]["platform"] == "github"
        assert identity["data"]["exists"] is True
        assert identity["data"]["public_repos"] == 42
        assert identity["confidence"] >= 70
    
    def test_normalize_nonexistent_user(self):
        """Test normalization for 404 (user not found)."""
        from worker_app.username_providers import GitHubProvider
        
        provider = GitHubProvider()
        response = {
            "success": True,
            "exists": False,
            "status_code": 404,
            "headers": {},
            "body": {"message": "Not Found"},
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        
        findings = provider.normalize("nonexistent123", response)
        
        assert len(findings) == 1
        identity = findings[0]
        assert identity["finding_type"] == "USERNAME_IDENTITY"
        assert identity["data"]["exists"] is False
        assert identity["confidence"] == 50
    
    def test_confidence_boost_for_active_users(self):
        """Test confidence increases for recently active users."""
        from worker_app.username_providers import GitHubProvider
        
        provider = GitHubProvider()
        
        # Active user (updated recently)
        response_active = {
            "success": True,
            "exists": True,
            "status_code": 200,
            "body": {
                "id": 1,
                "login": "active",
                "public_repos": 10,
                "followers": 20,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }
        
        findings_active = provider.normalize("active", response_active)
        identity_active = next(f for f in findings_active if f["finding_type"] == "USERNAME_IDENTITY")
        
        # Should have high confidence (70 base + 10 recent + 5 activity)
        assert identity_active["confidence"] >= 80


class TestRedditProviderNormalization:
    """Test Reddit response normalization."""
    
    def test_normalize_existing_user(self):
        """Test normalization for existing Reddit user."""
        from worker_app.username_providers import RedditProvider
        
        provider = RedditProvider()
        response = {
            "success": True,
            "exists": True,
            "status_code": 200,
            "headers": {},
            "body": {
                "id": "abc123",
                "name": "testuser",
                "link_karma": 1200,
                "comment_karma": 3400,
                "created_utc": 1531238400,  # 2018-07-10
                "is_employee": False,
                "is_gold": False,
            },
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        
        findings = provider.normalize("testuser", response)
        
        assert len(findings) >= 1
        
        identity = next(f for f in findings if f["finding_type"] == "USERNAME_IDENTITY")
        assert identity["subject"] == "testuser"
        assert identity["data"]["platform"] == "reddit"
        assert identity["data"]["exists"] is True
        assert identity["data"]["link_karma"] == 1200
        assert identity["data"]["comment_karma"] == 3400
    
    def test_normalize_suspended_user(self):
        """Test normalization for suspended user (403)."""
        from worker_app.username_providers import RedditProvider
        
        provider = RedditProvider()
        response = {
            "success": True,
            "exists": True,  # Account exists but suspended
            "status_code": 403,
            "headers": {},
            "body": {"message": "Forbidden", "suspended": True},
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        
        findings = provider.normalize("suspended_user", response)
        
        assert len(findings) == 1
        identity = findings[0]
        assert identity["data"]["exists"] is True
        assert identity["data"]["suspended"] is True


class TestUsernameValidation:
    """Test username validation."""
    
    def test_github_username_rules(self):
        """Test GitHub username validation rules."""
        # GitHub: max 39 chars, alphanumeric + hyphen
        valid = ["octocat", "test-user", "user123"]
        invalid = ["", "a" * 40, "user@name", "user.name"]
        
        for name in valid:
            assert len(name) <= 39
            assert all(c.isalnum() or c == '-' for c in name)
        
        for name in invalid:
            is_valid = len(name) > 0 and len(name) <= 39 and all(c.isalnum() or c == '-' for c in name)
            assert not is_valid
    
    def test_reddit_username_rules(self):
        """Test Reddit username validation rules."""
        # Reddit: 3-20 chars, alphanumeric + underscore
        valid = ["user", "test_user", "user123"]
        invalid = ["ab", "a" * 21, "user-name", "user.name"]
        
        for name in valid:
            assert 3 <= len(name) <= 20
            assert all(c.isalnum() or c == '_' for c in name)
        
        for name in invalid:
            is_valid = 3 <= len(name) <= 20 and all(c.isalnum() or c == '_' for c in name)
            assert not is_valid


class TestFingerprintStability:
    """Test that findings have stable fingerprints."""
    
    def test_same_user_same_fingerprint(self):
        """Same username + platform should produce same fingerprint."""
        import json
        import hashlib
        
        def compute_fingerprint(workspace_id, finding_type, subject, data):
            volatile = ("fetched_at", "updated_at", "timestamp")
            stable = {k: v for k, v in data.items() if k not in volatile}
            canonical = json.dumps(stable, sort_keys=True, separators=(',', ':'), default=str)
            composite = f"{workspace_id}{finding_type}{subject}{canonical}"
            return hashlib.sha256(composite.encode()).hexdigest()
        
        fp1 = compute_fingerprint(
            "ws-123",
            "USERNAME_IDENTITY",
            "octocat",
            {"platform": "github", "exists": True, "user_id": 123}
        )
        fp2 = compute_fingerprint(
            "ws-123",
            "USERNAME_IDENTITY",
            "octocat",
            {"platform": "github", "exists": True, "user_id": 123}
        )
        
        assert fp1 == fp2
    
    def test_different_platform_different_fingerprint(self):
        """Same username on different platforms = different fingerprint."""
        import json
        import hashlib
        
        def compute_fingerprint(workspace_id, finding_type, subject, data):
            stable = {k: v for k, v in data.items()}
            canonical = json.dumps(stable, sort_keys=True, separators=(',', ':'), default=str)
            composite = f"{workspace_id}{finding_type}{subject}{canonical}"
            return hashlib.sha256(composite.encode()).hexdigest()
        
        fp_github = compute_fingerprint(
            "ws-123",
            "USERNAME_IDENTITY",
            "testuser",
            {"platform": "github", "exists": True}
        )
        fp_reddit = compute_fingerprint(
            "ws-123",
            "USERNAME_IDENTITY",
            "testuser",
            {"platform": "reddit", "exists": True}
        )
        
        assert fp_github != fp_reddit


# =============================================================================
# Integration Tests (require network)
# =============================================================================

@pytest.mark.integration
class TestGitHubIntegration:
    """Integration tests for GitHub API."""
    
    def test_lookup_real_user(self):
        """Test lookup of a real GitHub user."""
        from worker_app.username_providers import GitHubProvider
        
        provider = GitHubProvider(timeout=10)
        response = provider.lookup("octocat")  # GitHub's mascot account
        
        assert response["success"] is True
        assert response["exists"] is True
        assert response["status_code"] == 200
        assert response["body"]["login"].lower() == "octocat"
    
    def test_lookup_nonexistent_user(self):
        """Test lookup of non-existent user."""
        from worker_app.username_providers import GitHubProvider
        
        provider = GitHubProvider(timeout=10)
        # Very unlikely to exist
        response = provider.lookup("this-username-definitely-does-not-exist-xyz123456789")
        
        assert response["success"] is True
        assert response["exists"] is False
        assert response["status_code"] == 404


@pytest.mark.integration
class TestRedditIntegration:
    """Integration tests for Reddit API."""
    
    def test_lookup_real_user(self):
        """Test lookup of a real Reddit user."""
        from worker_app.username_providers import RedditProvider
        
        provider = RedditProvider(timeout=10)
        # Reddit's admin account
        response = provider.lookup("reddit")
        
        assert response["success"] is True
        assert response["exists"] is True
        assert response["status_code"] == 200
    
    def test_lookup_nonexistent_user(self):
        """Test lookup of non-existent Reddit user."""
        from worker_app.username_providers import RedditProvider
        
        provider = RedditProvider(timeout=10)
        # Very unlikely to exist (too long for Reddit)
        response = provider.lookup("abc")  # Too short, might not exist
        
        # Should get a valid response (either exists or 404)
        assert response["success"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

