"""
Tests for V1 technique allowlist.

Only these techniques are allowed:
- domain_dns_lookup
- domain_whois_rdap_lookup
- username_github_lookup
- username_reddit_lookup
- email_mx_spf_dmarc_correlation
- email_breach_lookup
"""
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4


class TestTechniqueAllowlist:
    """Technique allowlist enforcement tests."""
    
    @pytest.fixture
    def target_id(self, client: TestClient, db, test_workspace, test_user, auth_headers):
        """Create a target for testing."""
        from app.models.target import Target, TargetType
        
        target = Target(
            id=uuid4(),
            workspace_id=test_workspace.id,
            created_by=test_user.id,
            target_type=TargetType.DOMAIN.value,
            value=f"allowlist-test-{uuid4()}.com",
        )
        db.add(target)
        db.commit()
        return str(target.id)
    
    # =========================================================================
    # Allowed techniques (should return 201)
    # =========================================================================
    
    @pytest.mark.parametrize("technique", [
        "domain_dns_lookup",
        "domain_whois_rdap_lookup",
    ])
    def test_allowed_domain_techniques(
        self, client: TestClient, test_workspace, auth_headers, target_id, technique
    ):
        """Allowed domain techniques return 201."""
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=auth_headers,
            json={
                "target_id": target_id,
                "technique_code": technique,
            },
        )
        assert response.status_code == 201, f"Failed for {technique}: {response.json()}"
    
    # =========================================================================
    # Blocked techniques (should return 400)
    # =========================================================================
    
    @pytest.mark.parametrize("technique,expected_error", [
        ("port_scan", "not enabled"),
        ("subdomain_enum", "not enabled"),
        ("cert_transparency", "not enabled"),
        ("screenshot", "not enabled"),
        ("email_verify", "not enabled"),  # Legacy
        ("social_lookup", "not enabled"),
        ("breach_check", "not enabled"),
        ("dns_lookup", "not enabled"),     # Legacy alias
        ("whois_lookup", "not enabled"),   # Legacy alias
    ])
    def test_blocked_techniques_return_400(
        self, client: TestClient, test_workspace, auth_headers, target_id, 
        technique, expected_error
    ):
        """Blocked techniques return 400 with clear error message."""
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=auth_headers,
            json={
                "target_id": target_id,
                "technique_code": technique,
            },
        )
        assert response.status_code == 400, f"Expected 400 for {technique}"
        assert expected_error in response.json()["detail"].lower()
    
    def test_nonexistent_technique_returns_400(
        self, client: TestClient, test_workspace, auth_headers, target_id
    ):
        """Non-existent technique returns 400."""
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=auth_headers,
            json={
                "target_id": target_id,
                "technique_code": "totally_fake_technique",
            },
        )
        assert response.status_code == 400
    
    # =========================================================================
    # Error message quality
    # =========================================================================
    
    def test_error_message_lists_enabled_techniques(
        self, client: TestClient, test_workspace, auth_headers, target_id
    ):
        """Error message should list enabled techniques."""
        response = client.post(
            f"/v1/workspaces/{test_workspace.id}/jobs",
            headers=auth_headers,
            json={
                "target_id": target_id,
                "technique_code": "port_scan",
            },
        )
        
        error = response.json()["detail"]
        assert "domain_dns_lookup" in error or "Enabled" in error


class TestConfigDrivenAllowlist:
    """Tests that allowlist is config-driven."""
    
    def test_settings_has_enabled_techniques(self):
        """Settings should have ENABLED_TECHNIQUES."""
        from app.core.config import settings
        
        assert hasattr(settings, "ENABLED_TECHNIQUES")
        assert len(settings.ENABLED_TECHNIQUES) >= 6
    
    def test_validate_technique_function(self):
        """validate_technique should raise for disabled techniques."""
        from app.core.config import validate_technique
        
        # Should not raise for enabled techniques
        validate_technique("domain_dns_lookup")
        
        # Should raise for disabled techniques
        with pytest.raises(ValueError) as exc:
            validate_technique("port_scan")
        
        assert "not enabled" in str(exc.value)
    
    def test_is_technique_enabled_method(self):
        """settings.is_technique_enabled should work correctly."""
        from app.core.config import settings
        
        assert settings.is_technique_enabled("domain_dns_lookup") is True
        assert settings.is_technique_enabled("port_scan") is False
        assert settings.is_technique_enabled("nonexistent") is False

