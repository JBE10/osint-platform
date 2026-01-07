"""
Email OSINT Providers.

Passive email analysis - NO active SMTP validation, NO bruteforce.

Techniques:
- EMAIL_MX_SPF_DMARC_CORRELATION: Analyze domain records
- EMAIL_BREACH_LOOKUP: Check breach databases (abstract provider)
"""
import dns.resolver
import hashlib
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional
import structlog

logger = structlog.get_logger()


# =============================================================================
# Email Domain Analyzer (Passive)
# =============================================================================

class EmailDomainAnalyzer:
    """
    Passive email domain analysis.
    
    Analyzes MX, SPF, DMARC records for the email domain.
    NO SMTP connection, NO mailbox probing.
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def analyze(self, email: str) -> dict:
        """
        Analyze email domain records.
        
        Returns:
        {
            "email": str,
            "domain": str,
            "local_part": str,
            "mx_records": [...],
            "spf_record": {...},
            "dmarc_record": {...},
            "mail_provider": str or None,
            "analysis_at": ISO timestamp,
        }
        """
        if "@" not in email:
            return {"error": "Invalid email format", "email": email}
        
        local_part, domain = email.rsplit("@", 1)
        analysis_at = datetime.now(timezone.utc).isoformat()
        
        result = {
            "email": email,
            "domain": domain,
            "local_part": local_part,
            "mx_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "mail_provider": None,
            "analysis_at": analysis_at,
            "errors": [],
        }
        
        # Get MX records
        try:
            mx_answers = self.resolver.resolve(domain, "MX")
            for rdata in mx_answers:
                result["mx_records"].append({
                    "host": str(rdata.exchange).rstrip("."),
                    "priority": rdata.preference,
                })
            result["mx_records"].sort(key=lambda x: x["priority"])
            
            # Detect mail provider from MX
            result["mail_provider"] = self._detect_provider(result["mx_records"])
        except dns.resolver.NXDOMAIN:
            result["errors"].append("Domain does not exist")
        except dns.resolver.NoAnswer:
            result["errors"].append("No MX records")
        except Exception as e:
            result["errors"].append(f"MX lookup failed: {str(e)}")
        
        # Get SPF record
        try:
            txt_answers = self.resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith("v=spf1"):
                    result["spf_record"] = self._parse_spf(txt_value)
                    break
        except Exception as e:
            result["errors"].append(f"SPF lookup failed: {str(e)}")
        
        # Get DMARC record
        try:
            dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in dmarc_answers:
                txt_value = str(rdata).strip('"')
                if "DMARC1" in txt_value:
                    result["dmarc_record"] = self._parse_dmarc(txt_value)
                    break
        except Exception as e:
            result["errors"].append(f"DMARC lookup failed: {str(e)}")
        
        return result
    
    def _detect_provider(self, mx_records: list) -> Optional[str]:
        """Detect email provider from MX records."""
        if not mx_records:
            return None
        
        primary_mx = mx_records[0]["host"].lower()
        
        providers = {
            "google": ["google.com", "googlemail.com", "aspmx.l.google.com"],
            "microsoft": ["outlook.com", "protection.outlook.com", "mail.protection.outlook.com"],
            "protonmail": ["protonmail.ch", "proton.me"],
            "zoho": ["zoho.com", "zoho.eu"],
            "fastmail": ["fastmail.com", "messagingengine.com"],
            "icloud": ["icloud.com", "me.com"],
            "yahoo": ["yahoodns.net", "yahoo.com"],
            "mailchimp": ["mandrillapp.com", "mailchimp.com"],
            "sendgrid": ["sendgrid.net"],
            "amazon_ses": ["amazonses.com", "awsdns"],
        }
        
        for provider, patterns in providers.items():
            for pattern in patterns:
                if pattern in primary_mx:
                    return provider
        
        return "custom"
    
    def _parse_spf(self, txt_value: str) -> dict:
        """Parse SPF record."""
        result = {
            "raw": txt_value,
            "version": "spf1",
            "mechanisms": [],
            "all_policy": None,
        }
        
        parts = txt_value.split()
        for part in parts[1:]:
            if part in ("-all", "~all", "?all", "+all"):
                qualifiers = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}
                result["all_policy"] = qualifiers.get(part[0], "pass") if part[0] in qualifiers else "pass"
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
            elif part.startswith("redirect="):
                result["mechanisms"].append({"type": "redirect", "value": part[9:]})
        
        return result
    
    def _parse_dmarc(self, txt_value: str) -> dict:
        """Parse DMARC record."""
        result = {
            "raw": txt_value,
            "version": "DMARC1",
            "policy": "none",
            "subdomain_policy": None,
            "pct": 100,
            "rua": [],
            "ruf": [],
        }
        
        parts = txt_value.replace(" ", "").split(";")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == "p":
                    result["policy"] = value
                elif key == "sp":
                    result["subdomain_policy"] = value
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


# =============================================================================
# Breach Lookup Provider (Abstract)
# =============================================================================

class BreachProvider(ABC):
    """Abstract base class for breach lookup providers."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass
    
    @abstractmethod
    def lookup(self, email: str) -> dict:
        """
        Check if email appears in known breaches.
        
        Returns:
        {
            "success": True/False,
            "email": str,
            "breached": True/False/None,
            "breach_count": int,
            "breaches": [...],
            "checked_at": ISO timestamp,
            "source": str,
        }
        """
        pass


class MockBreachProvider(BreachProvider):
    """
    Mock breach provider for testing.
    
    Returns fake data - use for development/testing only.
    Real providers (HIBP, etc) require API keys and have rate limits.
    """
    
    @property
    def name(self) -> str:
        return "mock"
    
    def lookup(self, email: str) -> dict:
        checked_at = datetime.now(timezone.utc).isoformat()
        
        # Simulate some known "breached" test emails
        test_breached = {
            "test@example.com": [
                {"name": "ExampleBreach2020", "date": "2020-03-15", "data_classes": ["Email", "Password"]},
            ],
            "breach@test.com": [
                {"name": "TestLeak2019", "date": "2019-07-22", "data_classes": ["Email", "Username"]},
                {"name": "DataDump2021", "date": "2021-01-10", "data_classes": ["Email", "Password", "Phone"]},
            ],
        }
        
        if email.lower() in test_breached:
            breaches = test_breached[email.lower()]
            return {
                "success": True,
                "email": email,
                "breached": True,
                "breach_count": len(breaches),
                "breaches": breaches,
                "checked_at": checked_at,
                "source": self.name,
                "_mock": True,
            }
        
        return {
            "success": True,
            "email": email,
            "breached": False,
            "breach_count": 0,
            "breaches": [],
            "checked_at": checked_at,
            "source": self.name,
            "_mock": True,
        }


class HIBPProvider(BreachProvider):
    """
    Have I Been Pwned provider.
    
    Requires API key for email queries.
    https://haveibeenpwned.com/API/v3
    
    Rate limit: 1 request per 1500ms with API key.
    """
    
    def __init__(self, api_key: Optional[str] = None, timeout: float = 10.0):
        self.api_key = api_key
        self.timeout = timeout
    
    @property
    def name(self) -> str:
        return "hibp"
    
    def lookup(self, email: str) -> dict:
        checked_at = datetime.now(timezone.utc).isoformat()
        
        if not self.api_key:
            return {
                "success": False,
                "email": email,
                "breached": None,
                "breach_count": 0,
                "breaches": [],
                "checked_at": checked_at,
                "source": self.name,
                "error": "API key required for HIBP",
            }
        
        import httpx
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": "OSINT-Platform/1.0 (security research)",
        }
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, headers=headers)
                
                if response.status_code == 200:
                    breaches = response.json()
                    return {
                        "success": True,
                        "email": email,
                        "breached": True,
                        "breach_count": len(breaches),
                        "breaches": [
                            {
                                "name": b.get("Name"),
                                "date": b.get("BreachDate"),
                                "data_classes": b.get("DataClasses", []),
                            }
                            for b in breaches
                        ],
                        "checked_at": checked_at,
                        "source": self.name,
                    }
                elif response.status_code == 404:
                    return {
                        "success": True,
                        "email": email,
                        "breached": False,
                        "breach_count": 0,
                        "breaches": [],
                        "checked_at": checked_at,
                        "source": self.name,
                    }
                elif response.status_code == 429:
                    return {
                        "success": False,
                        "email": email,
                        "breached": None,
                        "breach_count": 0,
                        "breaches": [],
                        "checked_at": checked_at,
                        "source": self.name,
                        "error": "rate_limit_exceeded",
                    }
                else:
                    return {
                        "success": False,
                        "email": email,
                        "breached": None,
                        "breach_count": 0,
                        "breaches": [],
                        "checked_at": checked_at,
                        "source": self.name,
                        "error": f"HTTP {response.status_code}",
                    }
        except Exception as e:
            return {
                "success": False,
                "email": email,
                "breached": None,
                "breach_count": 0,
                "breaches": [],
                "checked_at": checked_at,
                "source": self.name,
                "error": str(e),
            }


# =============================================================================
# Provider Chain
# =============================================================================

class BreachProviderChain:
    """Chain of breach providers with fallback."""
    
    def __init__(self, providers: list[BreachProvider]):
        self.providers = providers
    
    def lookup(self, email: str) -> dict:
        """Try each provider until one succeeds."""
        for provider in self.providers:
            result = provider.lookup(email)
            if result.get("success"):
                return result
        
        # All failed, return last result
        if self.providers:
            return self.providers[-1].lookup(email)
        
        return {
            "success": False,
            "email": email,
            "breached": None,
            "breach_count": 0,
            "breaches": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "source": "none",
            "error": "No providers available",
        }


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_email_domain(email: str, timeout: float = 5.0) -> dict:
    """Analyze email domain records (MX, SPF, DMARC)."""
    analyzer = EmailDomainAnalyzer(timeout=timeout)
    return analyzer.analyze(email)


def check_email_breach(email: str, hibp_api_key: Optional[str] = None) -> dict:
    """
    Check email in breach databases.
    
    Uses HIBP if API key provided, otherwise falls back to mock.
    """
    providers = []
    
    if hibp_api_key:
        providers.append(HIBPProvider(api_key=hibp_api_key))
    
    # Always add mock as fallback
    providers.append(MockBreachProvider())
    
    chain = BreachProviderChain(providers)
    return chain.lookup(email)


def get_email_hash(email: str) -> dict:
    """
    Generate email hashes for privacy-preserving lookups.
    
    Returns SHA1, SHA256, MD5 hashes of normalized email.
    """
    normalized = email.lower().strip()
    
    return {
        "email": email,
        "normalized": normalized,
        "sha1": hashlib.sha1(normalized.encode()).hexdigest(),
        "sha256": hashlib.sha256(normalized.encode()).hexdigest(),
        "md5": hashlib.md5(normalized.encode()).hexdigest(),
    }

