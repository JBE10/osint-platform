"""
Integration tests for OSINT techniques.

These tests require:
- Network access for real domain lookups
- Running services (docker compose up)
"""
import pytest
import dns.resolver
import httpx
import re

# Skip all tests if network is unavailable
pytestmark = pytest.mark.integration


# ============================================================================
# DNS Lookup Integration Tests
# ============================================================================

class TestDomainDnsLookup:
    """Integration tests for DNS lookups."""
    
    def test_real_domain_dns_lookup(self):
        """Test DNS lookup on example.com (IANA reserved)."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # A records
        try:
            answers = resolver.resolve("example.com", "A")
            a_records = [str(rdata) for rdata in answers]
            assert len(a_records) > 0
            # Verify we got valid IPv4 addresses
            for ip in a_records:
                parts = ip.split(".")
                assert len(parts) == 4
                assert all(0 <= int(p) <= 255 for p in parts)
        except dns.resolver.NXDOMAIN:
            pytest.fail("example.com should exist")
    
    def test_mx_records_lookup(self):
        """Test MX record lookup on google.com."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        try:
            answers = resolver.resolve("google.com", "MX")
            mx_records = [(str(rdata.exchange), rdata.preference) for rdata in answers]
            assert len(mx_records) > 0
            # Google has multiple MX servers
            assert any("google" in mx[0].lower() for mx in mx_records)
        except dns.resolver.NoAnswer:
            pytest.skip("No MX records found")
    
    def test_txt_spf_lookup(self):
        """Test TXT record lookup for SPF."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        try:
            answers = resolver.resolve("google.com", "TXT")
            txt_records = [str(rdata).strip('"') for rdata in answers]
            
            # Should have at least one SPF record
            spf_records = [txt for txt in txt_records if txt.startswith("v=spf1")]
            assert len(spf_records) > 0
        except dns.resolver.NoAnswer:
            pytest.skip("No TXT records found")
    
    def test_invalid_domain_rejected(self):
        """Test that invalid domains are properly rejected."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        
        with pytest.raises((dns.resolver.NXDOMAIN, dns.resolver.NoNameservers)):
            resolver.resolve("this-domain-definitely-does-not-exist-xyz123.invalid", "A")
    
    def test_dmarc_lookup(self):
        """Test DMARC record lookup."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        try:
            answers = resolver.resolve("_dmarc.google.com", "TXT")
            txt_records = [str(rdata).strip('"') for rdata in answers]
            
            # Should have DMARC record
            dmarc_records = [txt for txt in txt_records if "DMARC1" in txt]
            assert len(dmarc_records) > 0
            assert "p=" in dmarc_records[0]
        except dns.resolver.NoAnswer:
            pytest.skip("No DMARC record found")
    
    def test_ns_records(self):
        """Test NS record lookup."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        answers = resolver.resolve("example.com", "NS")
        ns_records = [str(rdata) for rdata in answers]
        
        assert len(ns_records) > 0


# ============================================================================
# RDAP Integration Tests
# ============================================================================

class TestDomainRdapLookup:
    """Integration tests for RDAP lookups."""
    
    IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
    
    def test_rdap_bootstrap_accessible(self):
        """Test that IANA RDAP bootstrap is accessible."""
        with httpx.Client(timeout=10) as client:
            response = client.get(self.IANA_BOOTSTRAP)
            assert response.status_code == 200
            
            data = response.json()
            assert "services" in data
            assert len(data["services"]) > 0
    
    def test_rdap_com_lookup(self):
        """Test RDAP lookup for .com domain."""
        # Get RDAP server for .com
        with httpx.Client(timeout=10) as client:
            response = client.get(self.IANA_BOOTSTRAP)
            bootstrap = response.json()
            
            # Find .com server
            com_server = None
            for service in bootstrap["services"]:
                if "com" in service[0]:
                    com_server = service[1][0]
                    break
            
            if not com_server:
                pytest.skip("No .com RDAP server found")
            
            # Query example.com
            if not com_server.endswith("/"):
                com_server += "/"
            
            rdap_url = f"{com_server}domain/example.com"
            response = client.get(rdap_url, follow_redirects=True)
            
            # RDAP should return data or error properly
            assert response.status_code in [200, 404, 429]
            
            if response.status_code == 200:
                data = response.json()
                # Should have standard RDAP fields
                assert "objectClassName" in data or "ldhName" in data
    
    def test_invalid_domain_rdap(self):
        """Test RDAP for invalid domain."""
        rdap_url = "https://rdap.verisign.com/com/v1/domain/this-does-not-exist-xyz123.com"
        
        with httpx.Client(timeout=10) as client:
            response = client.get(rdap_url, follow_redirects=True)
            # Should return 404 for non-existent domain
            assert response.status_code in [404, 400]


# ============================================================================
# Domain Validation Tests
# ============================================================================

class TestDomainValidation:
    """Tests for domain input validation."""
    
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    BLOCKED_TLDS = {"onion", "local", "localhost", "internal", "test", "invalid"}
    
    def validate_domain(self, domain: str) -> dict:
        """Validate domain for OSINT lookup."""
        domain = domain.lower().strip()
        
        if not self.DOMAIN_REGEX.match(domain):
            return {"valid": False, "error": "Invalid domain format"}
        
        tld = domain.split(".")[-1]
        if tld in self.BLOCKED_TLDS:
            return {"valid": False, "error": f"Blocked TLD: {tld}"}
        
        if len(domain) > 253:
            return {"valid": False, "error": "Domain too long"}
        
        return {"valid": True, "domain": domain}
    
    def test_valid_domains(self):
        """Test valid domain formats."""
        valid = ["example.com", "sub.example.com", "a.b.c.example.co.uk"]
        for domain in valid:
            result = self.validate_domain(domain)
            assert result["valid"], f"{domain} should be valid"
    
    def test_blocked_tlds(self):
        """Test that blocked TLDs are rejected."""
        blocked = ["site.onion", "server.local", "test.invalid"]
        for domain in blocked:
            result = self.validate_domain(domain)
            assert not result["valid"], f"{domain} should be blocked"
    
    def test_invalid_formats(self):
        """Test invalid domain formats."""
        invalid = [
            "notadomain",           # No TLD
            "-invalid.com",         # Starts with hyphen
            "http://example.com",   # URL not domain
            "example .com",         # Space
            "../etc/passwd",        # Path traversal
            "*.wildcard.com",       # Wildcard
        ]
        for domain in invalid:
            result = self.validate_domain(domain)
            assert not result["valid"], f"{domain} should be invalid"


# ============================================================================
# Rate Limiting Tests
# ============================================================================

class TestRateLimiting:
    """Tests for rate limiting behavior."""
    
    def test_token_bucket_logic(self):
        """Test token bucket rate limiter logic."""
        import time
        
        class SimpleTokenBucket:
            def __init__(self, rate: float, burst: int):
                self.rate = rate
                self.burst = burst
                self.tokens = burst
                self.last_update = time.time()
            
            def acquire(self) -> bool:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                return False
        
        # 1 token/second, burst of 2
        bucket = SimpleTokenBucket(rate=1.0, burst=2)
        
        # Should allow burst
        assert bucket.acquire() is True
        assert bucket.acquire() is True
        
        # Should deny after burst exhausted
        assert bucket.acquire() is False
        
        # After waiting, should allow again
        time.sleep(1.1)
        assert bucket.acquire() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])

