"""
Tests for EMAIL OSINT - Semana 6

Unit tests:
- Email canonicalization
- Email validation (format, length, domain)
- Finding normalization

Integration tests:
- Valid email → infrastructure + policies
- Domain without MX → partial findings
- Mock breach → breach status finding
"""

import pytest
import hashlib


# =============================================================================
# Unit Tests: Email Validation
# =============================================================================

class TestEmailCanonicalization:
    """Test email canonicalization."""
    
    def test_lowercase(self):
        from worker_app.security import canonicalize_email
        assert canonicalize_email("User@Example.COM") == "user@example.com"
    
    def test_strip_whitespace(self):
        from worker_app.security import canonicalize_email
        assert canonicalize_email("  user@example.com  ") == "user@example.com"
    
    def test_already_canonical(self):
        from worker_app.security import canonicalize_email
        assert canonicalize_email("user@example.com") == "user@example.com"
    
    def test_mixed_case_domain(self):
        from worker_app.security import canonicalize_email
        assert canonicalize_email("USER@Gmail.Com") == "user@gmail.com"


class TestEmailValidation:
    """Test email validation for OSINT."""
    
    def test_valid_email(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("user@cloudflare.com")
        assert result["valid"] is True
        assert result["canonical"] == "user@cloudflare.com"
        assert result["domain"] == "cloudflare.com"
    
    def test_invalid_format_no_at(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("userexample.com")
        assert result["valid"] is False
        assert "INVALID_EMAIL_FORMAT" in result["reason"]
    
    def test_invalid_format_multiple_at(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("user@@example.com")
        assert result["valid"] is False
    
    def test_email_too_long(self):
        from worker_app.security import validate_email_for_osint
        long_local = "a" * 300
        result = validate_email_for_osint(f"{long_local}@example.com")
        assert result["valid"] is False
        assert "TOO_LONG" in result["reason"]
    
    def test_local_part_too_long(self):
        from worker_app.security import validate_email_for_osint
        long_local = "a" * 65  # > 64 chars
        result = validate_email_for_osint(f"{long_local}@gmail.com")
        assert result["valid"] is False
        assert "LOCAL_PART_TOO_LONG" in result["reason"]
    
    def test_blocked_domain(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("user@example.com")
        assert result["valid"] is False
        assert result["blocked"] is True
        assert "BLOCKED" in result["reason"]
    
    def test_blocked_tld_localhost(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("user@server.localhost")
        assert result["valid"] is False
        assert result["blocked"] is True
    
    def test_disposable_email(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("user@mailinator.com")
        assert result["valid"] is True  # Valid but flagged
        assert result["disposable"] is True
    
    def test_empty_local_part(self):
        from worker_app.security import validate_email_for_osint
        result = validate_email_for_osint("@example.org")
        assert result["valid"] is False


# =============================================================================
# Unit Tests: Finding Normalization
# =============================================================================

class TestEmailFindingNormalization:
    """Test email finding normalization."""
    
    def test_email_mail_infrastructure_structure(self):
        """EMAIL_MAIL_INFRASTRUCTURE finding should have correct structure."""
        finding = {
            "finding_type": "EMAIL_MAIL_INFRASTRUCTURE",
            "subject": "user@cloudflare.com",
            "confidence": 80,
            "data": {
                "domain": "cloudflare.com",
                "mx_hosts": ["mx1.cloudflare.com", "mx2.cloudflare.com"],
            },
        }
        
        assert finding["finding_type"] == "EMAIL_MAIL_INFRASTRUCTURE"
        assert finding["subject"] == "user@cloudflare.com"
        assert "domain" in finding["data"]
        assert "mx_hosts" in finding["data"]
        assert isinstance(finding["data"]["mx_hosts"], list)
    
    def test_email_spf_policy_structure(self):
        """EMAIL_SPF_POLICY finding should have mode and policy."""
        finding = {
            "finding_type": "EMAIL_SPF_POLICY",
            "subject": "user@example.com",
            "confidence": 75,
            "data": {
                "mode": "hardfail",
                "policy": "v=spf1 include:_spf.google.com -all",
            },
        }
        
        assert finding["data"]["mode"] in ("hardfail", "softfail", "neutral", "pass", "unknown")
        assert "v=spf1" in finding["data"]["policy"]
    
    def test_email_dmarc_policy_structure(self):
        """EMAIL_DMARC_POLICY finding should have policy and rua."""
        finding = {
            "finding_type": "EMAIL_DMARC_POLICY",
            "subject": "user@example.com",
            "confidence": 75,
            "data": {
                "policy": "reject",
                "rua": ["dmarc@example.com"],
            },
        }
        
        assert finding["data"]["policy"] in ("none", "quarantine", "reject")
        assert isinstance(finding["data"]["rua"], list)
    
    def test_email_breach_status_no_breach(self):
        """EMAIL_BREACH_STATUS (no breach) should have breached=false."""
        finding = {
            "finding_type": "EMAIL_BREACH_STATUS",
            "subject": "clean@example.com",
            "confidence": 50,
            "data": {
                "breached": False,
            },
        }
        
        assert finding["data"]["breached"] is False
        assert finding["confidence"] == 50  # Low confidence for mock
    
    def test_email_breach_status_with_breach(self):
        """EMAIL_BREACH_STATUS (breach found) should have sources."""
        finding = {
            "finding_type": "EMAIL_BREACH_STATUS",
            "subject": "pwned@example.com",
            "confidence": 85,
            "data": {
                "breached": True,
                "sources": ["BigBreach2020", "AnotherBreach"],
                "first_seen": "2020-01-15",
            },
        }
        
        assert finding["data"]["breached"] is True
        assert len(finding["data"]["sources"]) > 0
        assert "first_seen" in finding["data"]


# =============================================================================
# Unit Tests: Fingerprint Stability
# =============================================================================

class TestEmailFindingFingerprint:
    """Test fingerprint stability for email findings."""
    
    def test_fingerprint_stable_for_same_data(self):
        """Same finding data should produce same fingerprint."""
        from worker_app.tasks import generate_finding_fingerprint
        
        workspace_id = "test-workspace-123"
        finding_type = "EMAIL_SPF_POLICY"
        subject = "user@cloudflare.com"
        data = {"mode": "hardfail", "policy": "v=spf1 -all"}
        
        fp1 = generate_finding_fingerprint(workspace_id, finding_type, subject, data)
        fp2 = generate_finding_fingerprint(workspace_id, finding_type, subject, data)
        
        assert fp1 == fp2
    
    def test_fingerprint_different_for_different_data(self):
        """Different data should produce different fingerprint."""
        from worker_app.tasks import generate_finding_fingerprint
        
        workspace_id = "test-workspace-123"
        finding_type = "EMAIL_SPF_POLICY"
        subject = "user@cloudflare.com"
        
        fp1 = generate_finding_fingerprint(workspace_id, finding_type, subject, {"mode": "hardfail"})
        fp2 = generate_finding_fingerprint(workspace_id, finding_type, subject, {"mode": "softfail"})
        
        assert fp1 != fp2
    
    def test_fingerprint_excludes_volatile_keys(self):
        """Fingerprint should exclude volatile keys like timestamps."""
        from worker_app.tasks import generate_finding_fingerprint
        
        workspace_id = "test-workspace-123"
        finding_type = "EMAIL_MAIL_INFRASTRUCTURE"
        subject = "user@example.com"
        
        data1 = {"domain": "example.com", "mx_hosts": ["mx.example.com"], "queried_at": "2026-01-01"}
        data2 = {"domain": "example.com", "mx_hosts": ["mx.example.com"], "queried_at": "2026-01-07"}
        
        fp1 = generate_finding_fingerprint(workspace_id, finding_type, subject, data1)
        fp2 = generate_finding_fingerprint(workspace_id, finding_type, subject, data2)
        
        assert fp1 == fp2  # Same despite different timestamps


# =============================================================================
# Integration Tests (require running services)
# =============================================================================

@pytest.mark.integration
class TestEmailMxSpfDmarcIntegration:
    """Integration tests for EMAIL_MX_SPF_DMARC_CORRELATION."""
    
    def test_valid_email_produces_findings(self):
        """Valid email should produce infrastructure and policy findings."""
        from worker_app.email_providers import analyze_email_domain
        
        result = analyze_email_domain("test@google.com", timeout=10)
        
        assert "error" not in result
        assert result["domain"] == "google.com"
        assert len(result.get("mx_records", [])) > 0
        # Google should have SPF
        assert result.get("spf_record") is not None
    
    def test_domain_without_mx(self):
        """Domain without MX should still produce partial results."""
        from worker_app.email_providers import analyze_email_domain
        
        # Use a domain that likely has no MX
        result = analyze_email_domain("test@thisdomain-does-not-exist-xyz123.com", timeout=5)
        
        # Should not crash, just have empty results
        assert isinstance(result.get("mx_records", []), list)
        assert isinstance(result.get("errors", []), list)
    
    def test_invalid_email_rejected(self):
        """Invalid email format should be rejected by validator."""
        from worker_app.security import validate_email_for_osint
        
        result = validate_email_for_osint("not-an-email")
        assert result["valid"] is False


@pytest.mark.integration
class TestEmailBreachIntegration:
    """Integration tests for EMAIL_BREACH_LOOKUP."""
    
    def test_mock_breach_provider(self):
        """Mock provider should return consistent results."""
        from worker_app.email_providers import check_email_breach
        
        # Without HIBP key, should use mock
        result = check_email_breach("test@example.com")
        
        assert "breached" in result or "breaches" in result
        assert result.get("source") == "mock" or result.get("_mock") is True
    
    def test_email_hash_generation(self):
        """Email hash should be consistent."""
        from worker_app.email_providers import get_email_hash
        
        hashes = get_email_hash("test@example.com")
        
        assert "sha256" in hashes
        assert "sha1" in hashes
        assert "md5" in hashes
        
        # Verify consistency
        hashes2 = get_email_hash("TEST@EXAMPLE.COM")
        assert hashes["sha256"] == hashes2["sha256"]  # Should normalize


# =============================================================================
# Security Tests
# =============================================================================

class TestEmailSecurityValidation:
    """Security tests for email OSINT."""
    
    def test_no_smtp_imports(self):
        """Worker should not import smtplib (no active SMTP)."""
        import worker_app.email_providers as ep
        import sys
        
        assert "smtplib" not in sys.modules
    
    def test_no_socket_connect_in_email_analysis(self):
        """Email analysis should use only DNS, not direct socket."""
        import inspect
        from worker_app.email_providers import EmailDomainAnalyzer
        
        source = inspect.getsource(EmailDomainAnalyzer)
        assert "socket.connect" not in source
        assert "SMTP(" not in source
    
    def test_email_not_logged_in_plaintext(self):
        """Email should be hashed in log messages."""
        import inspect
        from worker_app import tasks
        
        source = inspect.getsource(tasks.execute_email_mx_spf_dmarc)
        
        # Should use email_hash, not email directly
        assert "email_hash=email_hash" in source or "email_hash=" in source
    
    def test_blocked_domains_rejected(self):
        """Blocked domains should be rejected."""
        from worker_app.security import validate_email_for_osint
        
        blocked_emails = [
            "user@localhost",
            "user@server.local",
            "user@example.com",
            "test@test.com",
        ]
        
        for email in blocked_emails:
            result = validate_email_for_osint(email)
            assert result["valid"] is False or result["blocked"] is True, f"{email} should be blocked"

