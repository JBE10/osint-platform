"""
Security considerations for OSINT techniques.

Trade-offs and Risk Mitigations
===============================

WHY DOMAIN IS THE BEST FIRST TARGET:
------------------------------------
1. No PII directa - Domain lookups don't expose personal data
2. Highly correlatable - Domains link to IPs, emails, organizations
3. Passive standard sources - DNS, RDAP are non-intrusive

RISK 1: DNS Rebinding / SSRF Indirecto
--------------------------------------
Attack: Attacker provides domain that resolves to internal IPs
Mitigation: 
- We NEVER make HTTP requests to resolved IPs
- DNS resolver only queries public DNS servers
- Results are stored but not acted upon

RISK 2: RDAP Inconsistente entre TLDs
-------------------------------------
Attack: Different TLDs have different RDAP implementations
Mitigation:
- Provider interface with multiple RDAP endpoints
- Automatic fallback to WHOIS CLI
- Confidence scoring (RDAP=95, WHOIS CLI=85)

RISK 3: Datos Ruidosos (TXT Records)
------------------------------------
Attack: TXT records can contain arbitrary data, injection attempts
Mitigation:
- Conservative parsing (only SPF v=spf1, DMARC v=DMARC1)
- No execution of parsed content
- Confidence scoring based on parse success
- Data stored as-is but normalized separately

RISK 4: Rate Limiting / Abuse
-----------------------------
Attack: Rapid queries could trigger blocks from DNS/RDAP providers
Mitigation:
- Per-technique rate limiting (token bucket)
- Configurable limits per technique type
- Exponential backoff on failures
"""

import ipaddress
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)

# =============================================================================
# Trusted RDAP Providers (allowlist)
# =============================================================================

TRUSTED_RDAP_PROVIDERS = {
    # Generic TLDs
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "info": "https://rdap.afilias.net/rdap/info/domain/",
    
    # Country TLDs (examples)
    "uk": "https://rdap.nominet.uk/uk/domain/",
    "de": "https://rdap.denic.de/domain/",
    "eu": "https://rdap.eurid.eu/domain/",
    
    # New gTLDs (ICANN bootstrap)
    "_bootstrap": "https://rdap.org/domain/",
}


def get_rdap_url_for_domain(domain: str) -> Optional[str]:
    """
    Get trusted RDAP URL for a domain.
    Returns None if no trusted provider available.
    """
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return None
    
    tld = parts[-1]
    
    # Check direct TLD match
    if tld in TRUSTED_RDAP_PROVIDERS:
        return TRUSTED_RDAP_PROVIDERS[tld] + domain
    
    # Fallback to bootstrap
    return TRUSTED_RDAP_PROVIDERS["_bootstrap"] + domain


# =============================================================================
# IP Address Validation (prevent internal lookups)
# =============================================================================

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_resolved_ip(ip_str: str, domain: str) -> dict:
    """
    Validate a resolved IP address.
    Returns metadata about the IP including security flags.
    """
    result = {
        "ip": ip_str,
        "is_private": False,
        "is_valid": True,
        "security_note": None,
    }
    
    try:
        ip = ipaddress.ip_address(ip_str)
        result["is_private"] = is_private_ip(ip_str)
        
        if result["is_private"]:
            result["security_note"] = "RESOLVED_TO_PRIVATE_IP"
            logger.warning(
                "Domain resolved to private IP",
                domain=domain,
                ip=ip_str,
                security_flag="DNS_REBINDING_INDICATOR",
            )
    except ValueError:
        result["is_valid"] = False
        result["security_note"] = "INVALID_IP_FORMAT"
    
    return result


# =============================================================================
# TXT Record Sanitization
# =============================================================================

# Maximum length for TXT record parsing (prevent DoS)
MAX_TXT_LENGTH = 4096

# Patterns that indicate potential malicious content
SUSPICIOUS_TXT_PATTERNS = [
    "<script",
    "javascript:",
    "data:",
    "eval(",
    "document.",
    "window.",
]


def sanitize_txt_record(txt_value: str) -> dict:
    """
    Sanitize a TXT record value.
    Returns sanitized value with metadata.
    """
    result = {
        "original_length": len(txt_value),
        "truncated": False,
        "suspicious": False,
        "value": txt_value,
    }
    
    # Truncate if too long
    if len(txt_value) > MAX_TXT_LENGTH:
        result["value"] = txt_value[:MAX_TXT_LENGTH]
        result["truncated"] = True
        logger.warning("TXT record truncated", original_length=len(txt_value))
    
    # Check for suspicious patterns
    lower_value = txt_value.lower()
    for pattern in SUSPICIOUS_TXT_PATTERNS:
        if pattern in lower_value:
            result["suspicious"] = True
            logger.warning(
                "Suspicious TXT pattern detected",
                pattern=pattern,
                security_flag="SUSPICIOUS_TXT_CONTENT",
            )
            break
    
    return result


# =============================================================================
# Domain Validation
# =============================================================================

import re

# RFC 1035 compliant domain pattern
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Blocked TLDs (internal/reserved)
BLOCKED_TLDS = {
    "local",
    "localhost",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "test",
    "example",
    "invalid",
}


# =============================================================================
# Email Validation (canonicalization, length, domain)
# =============================================================================

# RFC 5321 limits
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_PART_LENGTH = 64

# Email pattern (simplified RFC 5322)
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Disposable email domains (common ones for blocking)
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "10minutemail.com",
    "fakeinbox.com",
    "trashmail.com",
    "getnada.com",
    "temp-mail.org",
}

# Blocked email domains (internal/reserved)
BLOCKED_EMAIL_DOMAINS = {
    "localhost",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "invalid.com",
}


def canonicalize_email(email: str) -> str:
    """
    Canonicalize email address for consistent processing.
    
    - Lowercase
    - Strip whitespace
    - Remove dots from Gmail local part (optional, configurable)
    - Handle plus addressing (keep for now, but normalize)
    """
    email = email.lower().strip()
    
    if "@" not in email:
        return email
    
    local, domain = email.rsplit("@", 1)
    
    # Gmail dot normalization (optional - disabled by default for privacy)
    # if domain in ("gmail.com", "googlemail.com"):
    #     local = local.replace(".", "")
    
    return f"{local}@{domain}"


def validate_email_for_osint(email: str) -> dict:
    """
    Validate an email address for OSINT operations.
    
    Checks:
    - Format (RFC 5322 simplified)
    - Length (RFC 5321 limits)
    - Domain validity (not blocked, not disposable)
    - Canonicalization
    
    Returns validation result with security metadata.
    """
    result = {
        "email": email,
        "canonical": None,
        "valid": False,
        "blocked": False,
        "disposable": False,
        "reason": None,
        "domain": None,
    }
    
    # Canonicalize
    canonical = canonicalize_email(email)
    result["canonical"] = canonical
    
    # Length check
    if len(canonical) > MAX_EMAIL_LENGTH:
        result["reason"] = "EMAIL_TOO_LONG"
        return result
    
    # Format check
    if not EMAIL_PATTERN.match(canonical):
        result["reason"] = "INVALID_EMAIL_FORMAT"
        return result
    
    # Extract parts
    if "@" not in canonical:
        result["reason"] = "MISSING_AT_SYMBOL"
        return result
    
    local, domain = canonical.rsplit("@", 1)
    result["domain"] = domain
    
    # Local part length
    if len(local) > MAX_LOCAL_PART_LENGTH:
        result["reason"] = "LOCAL_PART_TOO_LONG"
        return result
    
    # Empty local part
    if not local:
        result["reason"] = "EMPTY_LOCAL_PART"
        return result
    
    # Domain validation (reuse domain validator)
    domain_check = validate_domain_for_osint(domain)
    if not domain_check["valid"]:
        result["blocked"] = domain_check.get("blocked", False)
        result["reason"] = f"INVALID_DOMAIN: {domain_check['reason']}"
        return result
    
    # Check blocked domains
    if domain in BLOCKED_EMAIL_DOMAINS:
        result["blocked"] = True
        result["reason"] = f"BLOCKED_EMAIL_DOMAIN_{domain.upper()}"
        return result
    
    # Check disposable domains (warning, not blocking)
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        result["disposable"] = True
        logger.warning("Disposable email domain detected", domain=domain)
    
    result["valid"] = True
    return result


def validate_domain_for_osint(domain: str) -> dict:
    """
    Validate a domain for OSINT operations.
    Returns validation result with security metadata.
    """
    result = {
        "domain": domain,
        "valid": False,
        "blocked": False,
        "reason": None,
    }
    
    # Normalize
    domain = domain.lower().strip()
    
    # Check pattern
    if not DOMAIN_PATTERN.match(domain):
        result["reason"] = "INVALID_DOMAIN_FORMAT"
        return result
    
    # Check TLD
    tld = domain.split(".")[-1]
    if tld in BLOCKED_TLDS:
        result["blocked"] = True
        result["reason"] = f"BLOCKED_TLD_{tld.upper()}"
        return result
    
    # Check for IP literal (not a domain)
    try:
        ipaddress.ip_address(domain)
        result["reason"] = "IS_IP_NOT_DOMAIN"
        return result
    except ValueError:
        pass  # Good, it's not an IP
    
    result["valid"] = True
    return result

