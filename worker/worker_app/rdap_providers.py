"""
RDAP Provider Abstraction - V1

Providers for WHOIS/RDAP lookups with fallback chain.
"""
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
import httpx
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Base Provider Interface
# =============================================================================

class RdapProvider(ABC):
    """Abstract base class for RDAP providers."""
    
    @abstractmethod
    def lookup(self, domain: str) -> dict:
        """
        Lookup domain registration data.
        
        Returns dict with:
        - success: bool
        - source: str (provider name)
        - rdap_server: str (URL used)
        - response: dict (raw RDAP response)
        - error: str (if failed)
        """
        pass
    
    @abstractmethod
    def supports(self, domain: str) -> bool:
        """Check if this provider supports the given domain."""
        pass


# =============================================================================
# IANA Bootstrap RDAP Provider
# =============================================================================

# IANA RDAP Bootstrap servers per TLD
# Source: https://data.iana.org/rdap/dns.json
RDAP_SERVERS = {
    # Generic TLDs
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.afilias.net/rdap/info/",
    "biz": "https://rdap.nic.biz/",
    "io": "https://rdap.nic.io/",
    "co": "https://rdap.nic.co/",
    "me": "https://rdap.nic.me/",
    "tv": "https://rdap.nic.tv/",
    
    # Country TLDs
    "uk": "https://rdap.nominet.uk/uk/",
    "de": "https://rdap.denic.de/",
    "nl": "https://rdap.sidn.nl/",
    "eu": "https://rdap.eurid.eu/",
    "fr": "https://rdap.nic.fr/",
    "it": "https://rdap.nic.it/",
    "es": "https://rdap.nic.es/",
    "be": "https://rdap.dns.be/",
    "ch": "https://rdap.nic.ch/",
    "at": "https://rdap.nic.at/",
    "pl": "https://rdap.dns.pl/",
    "cz": "https://rdap.nic.cz/",
    "se": "https://rdap.iis.se/",
    "no": "https://rdap.norid.no/",
    "fi": "https://rdap.ficora.fi/",
    "dk": "https://rdap.dk-hostmaster.dk/",
    "au": "https://rdap.auda.org.au/",
    "nz": "https://rdap.nzrs.net.nz/",
    "ca": "https://rdap.ca.fury.ca/rdap/",
    "br": "https://rdap.registro.br/",
    "mx": "https://rdap.mx/",
    "jp": "https://rdap.jprs.jp/rdap/",
    "kr": "https://rdap.kr/",
    "cn": "https://rdap.cnnic.cn/",
    "in": "https://rdap.registry.in/",
    "ru": "https://rdap.tcinet.ru/",
    
    # New gTLDs (common)
    "app": "https://rdap.nic.google/",
    "dev": "https://rdap.nic.google/",
    "page": "https://rdap.nic.google/",
    "cloud": "https://rdap.nic.cloud/",
    "tech": "https://rdap.nic.tech/",
    "online": "https://rdap.nic.online/",
    "site": "https://rdap.nic.site/",
    "store": "https://rdap.nic.store/",
    "xyz": "https://rdap.nic.xyz/",
}


class IanaRdapProvider(RdapProvider):
    """
    IANA Bootstrap RDAP Provider.
    
    Uses IANA bootstrap registry to find correct RDAP server for TLD.
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.servers = RDAP_SERVERS.copy()
    
    def supports(self, domain: str) -> bool:
        """Check if we have an RDAP server for this TLD."""
        tld = self._get_tld(domain)
        return tld in self.servers
    
    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        parts = domain.lower().strip().split(".")
        return parts[-1] if parts else ""
    
    def _get_rdap_url(self, domain: str) -> Optional[str]:
        """Get RDAP URL for domain."""
        tld = self._get_tld(domain)
        base_url = self.servers.get(tld)
        if base_url:
            return f"{base_url}domain/{domain}"
        return None
    
    def lookup(self, domain: str) -> dict:
        """Perform RDAP lookup."""
        result = {
            "success": False,
            "source": "iana_rdap",
            "rdap_server": None,
            "response": None,
            "error": None,
        }
        
        rdap_url = self._get_rdap_url(domain)
        if not rdap_url:
            result["error"] = f"No RDAP server for TLD: {self._get_tld(domain)}"
            return result
        
        result["rdap_server"] = rdap_url.rsplit("/domain/", 1)[0] + "/"
        
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(rdap_url, headers={
                    "Accept": "application/rdap+json, application/json",
                })
                
                if response.status_code == 200:
                    result["success"] = True
                    result["response"] = response.json()
                elif response.status_code == 404:
                    result["error"] = f"Domain not found: {domain}"
                else:
                    result["error"] = f"HTTP {response.status_code}"
                    
        except httpx.TimeoutException:
            result["error"] = "Request timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result


# =============================================================================
# Mock RDAP Provider (for tests and fallback)
# =============================================================================

class MockRdapProvider(RdapProvider):
    """
    Mock RDAP Provider for testing and fallback.
    
    Returns synthetic data when real RDAP is unavailable.
    """
    
    def supports(self, domain: str) -> bool:
        """Always supports (fallback)."""
        return True
    
    def lookup(self, domain: str) -> dict:
        """Return mock RDAP response."""
        now = datetime.utcnow()
        
        return {
            "success": True,
            "source": "mock_rdap",
            "rdap_server": "mock://localhost/",
            "response": {
                "objectClassName": "domain",
                "ldhName": domain,
                "status": ["active"],
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2020-01-01T00:00:00Z",
                    },
                    {
                        "eventAction": "expiration",
                        "eventDate": "2030-01-01T00:00:00Z",
                    },
                ],
                "entities": [
                    {
                        "objectClassName": "entity",
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Mock Registrar Inc"]]
                        ],
                    }
                ],
                "nameservers": [
                    {"ldhName": "ns1.mock.example"},
                    {"ldhName": "ns2.mock.example"},
                ],
                "_mock": True,
                "_generated_at": now.isoformat() + "Z",
            },
            "error": None,
        }


# =============================================================================
# RDAP Response Parser
# =============================================================================

class RdapParser:
    """Parse RDAP responses into normalized data."""
    
    @staticmethod
    def extract_registrar(response: dict) -> Optional[dict]:
        """Extract registrar information."""
        entities = response.get("entities", [])
        for entity in entities:
            if "registrar" in entity.get("roles", []):
                name = None
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            name = item[3] if len(item) > 3 else None
                            break
                
                return {
                    "name": name,
                    "handle": entity.get("handle"),
                }
        return None
    
    @staticmethod
    def extract_dates(response: dict) -> dict:
        """Extract lifecycle dates."""
        dates = {
            "created_at": None,
            "expires_at": None,
            "updated_at": None,
        }
        
        events = response.get("events", [])
        for event in events:
            action = event.get("eventAction", "").lower()
            date = event.get("eventDate")
            
            if date:
                # Normalize date to YYYY-MM-DD
                if "T" in date:
                    date = date.split("T")[0]
                
                if action in ("registration", "registered"):
                    dates["created_at"] = date
                elif action in ("expiration", "expiry"):
                    dates["expires_at"] = date
                elif action in ("last changed", "last update", "updated"):
                    dates["updated_at"] = date
        
        return dates
    
    @staticmethod
    def extract_status(response: dict) -> list:
        """Extract domain status."""
        return response.get("status", [])
    
    @staticmethod
    def extract_nameservers(response: dict) -> list:
        """Extract nameservers."""
        nameservers = response.get("nameservers", [])
        return [
            ns.get("ldhName", "").lower().rstrip(".")
            for ns in nameservers
            if ns.get("ldhName")
        ]


# =============================================================================
# Provider Chain (with fallback)
# =============================================================================

class RdapProviderChain:
    """
    Chain of RDAP providers with automatic fallback.
    
    Tries providers in order until one succeeds.
    """
    
    def __init__(self, providers: list[RdapProvider] = None):
        self.providers = providers or [
            IanaRdapProvider(),
            MockRdapProvider(),  # Fallback
        ]
    
    def lookup(self, domain: str) -> dict:
        """
        Lookup domain using provider chain.
        
        Returns result from first successful provider.
        """
        errors = []
        
        for provider in self.providers:
            if not provider.supports(domain):
                continue
            
            result = provider.lookup(domain)
            
            if result["success"]:
                logger.info(
                    "RDAP lookup successful",
                    domain=domain,
                    source=result["source"],
                )
                return result
            
            errors.append(f"{provider.__class__.__name__}: {result.get('error')}")
        
        # All providers failed
        logger.warning("All RDAP providers failed", domain=domain, errors=errors)
        
        return {
            "success": False,
            "source": "none",
            "rdap_server": None,
            "response": None,
            "error": "; ".join(errors),
        }


# =============================================================================
# Convenience function
# =============================================================================

def rdap_lookup(domain: str, timeout: float = 10.0) -> dict:
    """
    Perform RDAP lookup with automatic provider selection and fallback.
    
    Returns:
    {
        "success": True/False,
        "source": "iana_rdap" | "mock_rdap",
        "rdap_server": "https://...",
        "response": {...},  # Raw RDAP response
        "error": None | "error message",
    }
    """
    chain = RdapProviderChain([
        IanaRdapProvider(timeout=timeout),
        MockRdapProvider(),
    ])
    return chain.lookup(domain)

