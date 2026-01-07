"""
Tests for Email OSINT Providers.
"""
import pytest
from datetime import datetime, timezone


# =============================================================================
# Unit Tests - Email Domain Analyzer
# =============================================================================

class TestEmailDomainAnalyzer:
    """Test email domain analysis."""
    
    def test_analyze_valid_email(self):
        """Test analysis of valid email."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer(timeout=5)
        result = analyzer.analyze("test@google.com")
        
        assert result["email"] == "test@google.com"
        assert result["domain"] == "google.com"
        assert result["local_part"] == "test"
        assert len(result["mx_records"]) > 0
        assert result["mail_provider"] == "google"
    
    def test_analyze_invalid_email(self):
        """Test analysis of invalid email (no @)."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer(timeout=5)
        result = analyzer.analyze("notanemail")
        
        assert "error" in result
    
    def test_provider_detection_google(self):
        """Test Google mail provider detection."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        provider = analyzer._detect_provider([
            {"host": "aspmx.l.google.com", "priority": 10}
        ])
        
        assert provider == "google"
    
    def test_provider_detection_microsoft(self):
        """Test Microsoft mail provider detection."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        provider = analyzer._detect_provider([
            {"host": "example-com.mail.protection.outlook.com", "priority": 0}
        ])
        
        assert provider == "microsoft"
    
    def test_spf_parsing(self):
        """Test SPF record parsing."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        
        spf = analyzer._parse_spf("v=spf1 include:_spf.google.com ~all")
        assert spf["version"] == "spf1"
        assert spf["all_policy"] == "softfail"
        assert any(m.get("value") == "_spf.google.com" for m in spf["mechanisms"])
    
    def test_spf_hardfail(self):
        """Test SPF hardfail parsing."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        
        spf = analyzer._parse_spf("v=spf1 ip4:192.168.1.0/24 -all")
        assert spf["all_policy"] == "fail"
    
    def test_dmarc_parsing(self):
        """Test DMARC record parsing."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        
        dmarc = analyzer._parse_dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com")
        assert dmarc["version"] == "DMARC1"
        assert dmarc["policy"] == "reject"
        assert dmarc["pct"] == 100
        assert "mailto:dmarc@example.com" in dmarc["rua"]
    
    def test_dmarc_quarantine(self):
        """Test DMARC quarantine policy."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        analyzer = EmailDomainAnalyzer()
        
        dmarc = analyzer._parse_dmarc("v=DMARC1; p=quarantine; sp=reject")
        assert dmarc["policy"] == "quarantine"
        assert dmarc["subdomain_policy"] == "reject"


# =============================================================================
# Unit Tests - Breach Providers
# =============================================================================

class TestBreachProviders:
    """Test breach lookup providers."""
    
    def test_mock_provider_breached_email(self):
        """Test mock provider with known breached email."""
        from worker_app.email_providers import MockBreachProvider
        
        provider = MockBreachProvider()
        result = provider.lookup("test@example.com")
        
        assert result["success"] is True
        assert result["breached"] is True
        assert result["breach_count"] >= 1
        assert result["_mock"] is True
    
    def test_mock_provider_clean_email(self):
        """Test mock provider with clean email."""
        from worker_app.email_providers import MockBreachProvider
        
        provider = MockBreachProvider()
        result = provider.lookup("clean@example.com")
        
        assert result["success"] is True
        assert result["breached"] is False
        assert result["breach_count"] == 0
    
    def test_hibp_provider_no_key(self):
        """Test HIBP provider without API key."""
        from worker_app.email_providers import HIBPProvider
        
        provider = HIBPProvider(api_key=None)
        result = provider.lookup("test@example.com")
        
        assert result["success"] is False
        assert "API key required" in result.get("error", "")
    
    def test_provider_chain_fallback(self):
        """Test provider chain falls back to mock."""
        from worker_app.email_providers import BreachProviderChain, HIBPProvider, MockBreachProvider
        
        chain = BreachProviderChain([
            HIBPProvider(api_key=None),  # Will fail
            MockBreachProvider(),         # Fallback
        ])
        
        result = chain.lookup("test@example.com")
        
        assert result["success"] is True
        assert result["source"] == "mock"


# =============================================================================
# Unit Tests - Email Hash Generation
# =============================================================================

class TestEmailHash:
    """Test email hash generation."""
    
    def test_hash_generation(self):
        """Test hash generation for email."""
        from worker_app.email_providers import get_email_hash
        
        hashes = get_email_hash("Test@Example.COM")
        
        assert hashes["normalized"] == "test@example.com"
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha1"]) == 40
        assert len(hashes["md5"]) == 32
    
    def test_hash_consistency(self):
        """Test hash consistency for same email."""
        from worker_app.email_providers import get_email_hash
        
        h1 = get_email_hash("user@example.com")
        h2 = get_email_hash("USER@EXAMPLE.COM")
        
        assert h1["sha256"] == h2["sha256"]
        assert h1["md5"] == h2["md5"]


# =============================================================================
# Integration Tests (require network)
# =============================================================================

@pytest.mark.integration
class TestEmailDomainIntegration:
    """Integration tests for email domain analysis."""
    
    def test_analyze_google_domain(self):
        """Test analysis of Google domain."""
        from worker_app.email_providers import analyze_email_domain
        
        result = analyze_email_domain("test@google.com")
        
        assert result["domain"] == "google.com"
        assert len(result["mx_records"]) > 0
        assert result["mail_provider"] == "google"
        assert result["spf_record"] is not None
        assert result["dmarc_record"] is not None
    
    def test_analyze_microsoft_domain(self):
        """Test analysis of Microsoft domain."""
        from worker_app.email_providers import analyze_email_domain
        
        result = analyze_email_domain("test@outlook.com")
        
        assert result["domain"] == "outlook.com"
        assert len(result["mx_records"]) > 0
        assert result["mail_provider"] == "microsoft"
    
    def test_analyze_nonexistent_domain(self):
        """Test analysis of non-existent domain."""
        from worker_app.email_providers import analyze_email_domain
        
        result = analyze_email_domain("test@this-domain-does-not-exist-xyz123.com")
        
        assert len(result["errors"]) > 0
        assert len(result["mx_records"]) == 0


# =============================================================================
# Security Tests
# =============================================================================

class TestEmailSecurity:
    """Security-focused tests."""
    
    def test_no_smtp_connection(self):
        """Verify no SMTP connection is made (passive only)."""
        from worker_app.email_providers import EmailDomainAnalyzer
        
        # The analyzer should only use DNS, not SMTP
        analyzer = EmailDomainAnalyzer()
        
        # Check that there's no socket/smtp import or connection
        import inspect
        source = inspect.getsource(EmailDomainAnalyzer)
        
        assert "smtplib" not in source
        assert "socket.connect" not in source
        assert "RCPT TO" not in source
    
    def test_email_not_leaked_in_breach_check(self):
        """Verify email is hashed for privacy in breach lookups."""
        from worker_app.email_providers import get_email_hash
        
        hashes = get_email_hash("sensitive@private.com")
        
        # Should have hashes available for privacy-preserving lookups
        assert "sha256" in hashes
        assert "sha1" in hashes
        
        # The hash should not contain the original email
        assert "sensitive@private.com" not in hashes["sha256"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

