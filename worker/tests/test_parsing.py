"""
Unit tests for SPF/DMARC parsing and fingerprint generation.
"""
import pytest
import json
import hashlib


# ============================================================================
# SPF Parsing Tests
# ============================================================================

def parse_spf_record(txt_value: str) -> dict | None:
    """Parse SPF record from TXT value."""
    if not txt_value.startswith("v=spf1"):
        return None
    
    result = {
        "version": "spf1",
        "mechanisms": [],
        "all_policy": None,
    }
    
    parts = txt_value.split()
    for part in parts[1:]:  # Skip v=spf1
        if part.startswith("+"):
            result["mechanisms"].append({"qualifier": "pass", "value": part[1:]})
        elif part.startswith("-"):
            if part == "-all":
                result["all_policy"] = {"qualifier": "fail"}
            else:
                result["mechanisms"].append({"qualifier": "fail", "value": part[1:]})
        elif part.startswith("~"):
            if part == "~all":
                result["all_policy"] = {"qualifier": "softfail"}
            else:
                result["mechanisms"].append({"qualifier": "softfail", "value": part[1:]})
        elif part.startswith("?"):
            if part == "?all":
                result["all_policy"] = {"qualifier": "neutral"}
            else:
                result["mechanisms"].append({"qualifier": "neutral", "value": part[1:]})
        elif part == "all" or part == "+all":
            result["all_policy"] = {"qualifier": "pass"}
        elif part.startswith("include:"):
            result["mechanisms"].append({"type": "include", "value": part[8:]})
        elif part.startswith("ip4:"):
            result["mechanisms"].append({"type": "ip4", "value": part[4:]})
        elif part.startswith("ip6:"):
            result["mechanisms"].append({"type": "ip6", "value": part[4:]})
        elif part.startswith("a:") or part == "a":
            result["mechanisms"].append({"type": "a", "value": part[2:] if ":" in part else ""})
        elif part.startswith("mx:") or part == "mx":
            result["mechanisms"].append({"type": "mx", "value": part[3:] if ":" in part else ""})
    
    return result


class TestSpfParsing:
    """Tests for SPF record parsing."""
    
    def test_basic_spf_softfail(self):
        """Test basic SPF with softfail."""
        spf = "v=spf1 include:_spf.google.com ~all"
        result = parse_spf_record(spf)
        
        assert result is not None
        assert result["version"] == "spf1"
        assert result["all_policy"]["qualifier"] == "softfail"
        assert any(m.get("value") == "_spf.google.com" for m in result["mechanisms"])
    
    def test_spf_hardfail(self):
        """Test SPF with hardfail (-all)."""
        spf = "v=spf1 ip4:192.168.1.0/24 -all"
        result = parse_spf_record(spf)
        
        assert result is not None
        assert result["all_policy"]["qualifier"] == "fail"
        assert any(m.get("value") == "192.168.1.0/24" for m in result["mechanisms"])
    
    def test_spf_neutral(self):
        """Test SPF with neutral (?all)."""
        spf = "v=spf1 mx ?all"
        result = parse_spf_record(spf)
        
        assert result is not None
        assert result["all_policy"]["qualifier"] == "neutral"
    
    def test_complex_spf(self):
        """Test complex SPF with multiple mechanisms."""
        spf = "v=spf1 a mx include:spf.protection.outlook.com ip4:10.0.0.0/8 ~all"
        result = parse_spf_record(spf)
        
        assert result is not None
        assert len(result["mechanisms"]) >= 4
        assert result["all_policy"]["qualifier"] == "softfail"
    
    def test_non_spf_record(self):
        """Test that non-SPF records return None."""
        txt = "google-site-verification=abc123"
        result = parse_spf_record(txt)
        
        assert result is None
    
    def test_empty_string(self):
        """Test empty string returns None."""
        result = parse_spf_record("")
        assert result is None


# ============================================================================
# DMARC Parsing Tests
# ============================================================================

def parse_dmarc_record(txt_value: str) -> dict | None:
    """Parse DMARC record from TXT value."""
    if not txt_value.startswith("v=DMARC1"):
        return None
    
    result = {
        "version": "DMARC1",
        "policy": "none",
        "rua": [],
        "ruf": [],
        "pct": 100,
        "sp": None,
    }
    
    # Parse key=value pairs
    parts = txt_value.replace(" ", "").split(";")
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key == "p":
                result["policy"] = value
            elif key == "sp":
                result["sp"] = value
            elif key == "pct":
                try:
                    result["pct"] = int(value)
                except ValueError:
                    pass
            elif key == "rua":
                result["rua"] = [r.strip() for r in value.split(",")]
            elif key == "ruf":
                result["ruf"] = [r.strip() for r in value.split(",")]
    
    return result


class TestDmarcParsing:
    """Tests for DMARC record parsing."""
    
    def test_basic_dmarc_none(self):
        """Test basic DMARC with p=none."""
        dmarc = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        result = parse_dmarc_record(dmarc)
        
        assert result is not None
        assert result["policy"] == "none"
        assert "mailto:dmarc@example.com" in result["rua"]
    
    def test_dmarc_reject(self):
        """Test DMARC with p=reject."""
        dmarc = "v=DMARC1; p=reject; pct=100"
        result = parse_dmarc_record(dmarc)
        
        assert result is not None
        assert result["policy"] == "reject"
        assert result["pct"] == 100
    
    def test_dmarc_quarantine(self):
        """Test DMARC with p=quarantine."""
        dmarc = "v=DMARC1; p=quarantine; sp=reject; pct=50"
        result = parse_dmarc_record(dmarc)
        
        assert result is not None
        assert result["policy"] == "quarantine"
        assert result["sp"] == "reject"
        assert result["pct"] == 50
    
    def test_dmarc_multiple_rua(self):
        """Test DMARC with multiple RUA addresses."""
        dmarc = "v=DMARC1; p=none; rua=mailto:a@x.com,mailto:b@y.com"
        result = parse_dmarc_record(dmarc)
        
        assert result is not None
        assert len(result["rua"]) == 2
    
    def test_non_dmarc_record(self):
        """Test that non-DMARC records return None."""
        txt = "v=spf1 -all"
        result = parse_dmarc_record(txt)
        
        assert result is None


# ============================================================================
# Fingerprint Stability Tests
# ============================================================================

def generate_finding_fingerprint(workspace_id: str, finding_type: str, subject: str, data: dict) -> str:
    """
    Generate fingerprint for deduplication.
    Must be stable across identical inputs.
    """
    volatile_keys = ("timestamp", "ttl", "cached_at", "query_time_ms", "last_checked", "queried_at")
    stable_data = {k: v for k, v in data.items() if k not in volatile_keys}
    canonical_json = json.dumps(stable_data, sort_keys=True, separators=(',', ':'), default=str)
    composite = f"{workspace_id}{finding_type}{subject}{canonical_json}"
    return hashlib.sha256(composite.encode()).hexdigest()


class TestFingerprintStability:
    """Tests for fingerprint generation stability."""
    
    def test_same_input_same_fingerprint(self):
        """Same inputs must produce identical fingerprints."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        
        assert fp1 == fp2
    
    def test_different_workspace_different_fingerprint(self):
        """Different workspaces must produce different fingerprints."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        fp2 = generate_finding_fingerprint(
            "ws-456",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        
        assert fp1 != fp2
    
    def test_key_order_does_not_affect_fingerprint(self):
        """Key order in data dict must not affect fingerprint (canonical JSON)."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"version": 4, "ip": "93.184.216.34"}  # Different order
        )
        
        assert fp1 == fp2
    
    def test_volatile_keys_excluded(self):
        """Volatile keys (ttl, timestamp, etc) must not affect fingerprint."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4, "ttl": 3600}  # Added TTL
        )
        fp3 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4, "queried_at": "2026-01-01T00:00:00Z"}
        )
        
        assert fp1 == fp2
        assert fp1 == fp3
    
    def test_different_data_different_fingerprint(self):
        """Different data must produce different fingerprints."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34", "version": 4}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "1.2.3.4", "version": 4}  # Different IP
        )
        
        assert fp1 != fp2
    
    def test_fingerprint_is_sha256(self):
        """Fingerprint must be a valid SHA256 hex string."""
        fp = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_IP_ADDRESS",
            "example.com",
            {"ip": "93.184.216.34"}
        )
        
        assert len(fp) == 64  # SHA256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in fp)


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_data(self):
        """Empty data dict should work."""
        fp = generate_finding_fingerprint("ws", "TYPE", "subject", {})
        assert len(fp) == 64
    
    def test_unicode_in_data(self):
        """Unicode characters should be handled correctly."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_REGISTRAR",
            "example.com",
            {"name": "Registrar Inc™"}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "DOMAIN_REGISTRAR",
            "example.com",
            {"name": "Registrar Inc™"}
        )
        
        assert fp1 == fp2
    
    def test_nested_data(self):
        """Nested dicts should be handled consistently."""
        fp1 = generate_finding_fingerprint(
            "ws-123",
            "COMPLEX",
            "test",
            {"outer": {"inner": "value", "num": 42}}
        )
        fp2 = generate_finding_fingerprint(
            "ws-123",
            "COMPLEX",
            "test",
            {"outer": {"num": 42, "inner": "value"}}  # Different inner order
        )
        
        assert fp1 == fp2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

