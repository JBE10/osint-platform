"""
Tests for security configurations.

- JWT secret validation in production
- Production safety checks
- Audit middleware
"""
import pytest
import os
from unittest.mock import patch


class TestProductionSafety:
    """Production safety check tests."""
    
    def test_dangerous_jwt_secret_detected(self):
        """Dangerous JWT secrets should be detected in production."""
        from app.core.config import Settings, DANGEROUS_DEFAULTS
        
        # Test each dangerous default
        for dangerous in DANGEROUS_DEFAULTS["JWT_SECRET_KEY"]:
            settings = Settings(
                ENV="prod",
                JWT_SECRET_KEY=dangerous,
            )
            errors = settings.validate_production_safety()
            assert any("JWT_SECRET_KEY" in e for e in errors), \
                f"Should detect dangerous JWT: {dangerous}"
    
    def test_short_jwt_secret_detected(self):
        """Short JWT secrets should be detected in production."""
        from app.core.config import Settings
        
        settings = Settings(
            ENV="prod",
            JWT_SECRET_KEY="short-key",  # Less than 32 chars
        )
        errors = settings.validate_production_safety()
        assert any("too short" in e for e in errors)
    
    def test_debug_in_prod_detected(self):
        """DEBUG=true should be detected in production."""
        from app.core.config import Settings
        
        settings = Settings(
            ENV="prod",
            JWT_SECRET_KEY="a" * 64,  # Valid length
            DEBUG=True,
        )
        errors = settings.validate_production_safety()
        assert any("DEBUG" in e for e in errors)
    
    def test_valid_prod_config_passes(self):
        """Valid production config should pass."""
        from app.core.config import Settings
        
        settings = Settings(
            ENV="prod",
            JWT_SECRET_KEY="a" * 64,
            DEBUG=False,
            MINIO_ACCESS_KEY="custom-key",
            MINIO_SECRET_KEY="custom-secret",
        )
        errors = settings.validate_production_safety()
        # Only noop_lookup warning if present
        critical_errors = [e for e in errors if "SECURITY ERROR" in e]
        assert len(critical_errors) == 0
    
    def test_local_env_skips_checks(self):
        """Local environment should skip production checks."""
        from app.core.config import Settings
        
        settings = Settings(
            ENV="local",
            JWT_SECRET_KEY="insecure",  # Would fail in prod
        )
        errors = settings.validate_production_safety()
        assert len(errors) == 0
    
    def test_is_production_property(self):
        """is_production property should work correctly."""
        from app.core.config import Settings
        
        local = Settings(ENV="local")
        assert local.is_production is False
        assert local.is_local is True
        
        prod = Settings(ENV="prod")
        assert prod.is_production is True
        assert prod.is_local is False


class TestAuditMiddleware:
    """Audit middleware tests."""
    
    def test_audit_action_detection(self):
        """Audit actions should be detected correctly."""
        from app.core.security_v1 import get_audit_action
        
        # Auth actions
        assert get_audit_action("POST", "/v1/auth/login") == "auth.login"
        assert get_audit_action("POST", "/v1/auth/register") == "auth.register"
        
        # Job actions (with UUID)
        uuid = "12345678-1234-1234-1234-123456789abc"
        assert get_audit_action("POST", f"/v1/workspaces/{uuid}/jobs") == "job.create"
        assert get_audit_action("POST", f"/v1/workspaces/{uuid}/jobs/{uuid}/enqueue") == "job.enqueue"
        
        # Target actions
        assert get_audit_action("POST", f"/v1/workspaces/{uuid}/targets/domain") == "target.create"
        
        # Export actions
        assert get_audit_action("GET", f"/v1/workspaces/{uuid}/findings/export/json") == "findings.export"
        
        # Non-audited action
        assert get_audit_action("GET", f"/v1/workspaces/{uuid}/jobs") is None
    
    def test_mutation_methods_are_audited(self, client, auth_headers, test_workspace):
        """POST/PUT/DELETE methods should be audited."""
        # This is an integration test - check audit log after mutation
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/targets/domain",
            headers=auth_headers,
            json={"domain": "audit-test.com"},
        )
        
        # Should succeed (201 for create)
        assert response.status_code == 201
        
        # Audit log should be created (check database)
        # This would require checking the audit_logs table


class TestJWTSecurity:
    """JWT security tests."""
    
    def test_jwt_cannot_be_tampered(self, client, test_user, auth_headers):
        """Tampered JWT should be rejected."""
        # Get valid token
        token = auth_headers["Authorization"].split(" ")[1]
        
        # Tamper with it
        tampered = token[:-5] + "XXXXX"
        
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert response.status_code == 401
    
    def test_expired_jwt_rejected(self, client, test_user):
        """Expired JWT should be rejected."""
        import jwt
        from datetime import datetime, timezone, timedelta
        from app.core.config import settings
        
        # Create token that's already expired
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(test_user.id),
            "email": test_user.email,
            "iat": now - timedelta(hours=1),
            "exp": now - timedelta(seconds=1),  # Already expired
        }
        expired_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
        
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401
    
    def test_jwt_with_wrong_algorithm_rejected(self, client, test_user):
        """JWT with wrong algorithm should be rejected."""
        import jwt
        
        # Create token with different algorithm
        payload = {"sub": str(test_user.id)}
        wrong_algo_token = jwt.encode(payload, "key", algorithm="HS384")
        
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {wrong_algo_token}"},
        )
        assert response.status_code == 401


class TestTechniqueBlocking:
    """Tests for technique blocking (security)."""
    
    def test_blocked_techniques_reduce_attack_surface(self):
        """Blocked techniques should include dangerous ones."""
        from app.core.config import DISABLED_TECHNIQUES
        
        dangerous = {"port_scan", "subdomain_enum"}
        assert dangerous.issubset(DISABLED_TECHNIQUES)
    
    def test_enabled_techniques_are_passive(self):
        """Enabled techniques should all be passive."""
        from app.core.config import DEFAULT_ENABLED_TECHNIQUES
        
        # All V1 techniques are passive (no active probing)
        passive_techniques = {
            "domain_dns_lookup",      # DNS queries only
            "domain_whois_rdap_lookup",  # Public WHOIS/RDAP
            "username_github_lookup",    # Public API
            "username_reddit_lookup",    # Public API
            "email_mx_spf_dmarc_correlation",  # DNS queries
            "email_breach_lookup",       # External API
        }
        
        assert DEFAULT_ENABLED_TECHNIQUES == passive_techniques

