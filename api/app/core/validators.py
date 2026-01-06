import re
from typing import Annotated
from pydantic import AfterValidator, ValidationError
from pydantic_core import PydanticCustomError


# =============================================================================
# Email Validator
# =============================================================================

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)
MAX_EMAIL_LENGTH = 254


def validate_email(value: str) -> str:
    """
    Validate and normalize email address.
    - RFC basic compliance
    - Lowercase + trim
    - Max length check
    """
    value = value.strip().lower()
    
    if len(value) > MAX_EMAIL_LENGTH:
        raise PydanticCustomError(
            "email_too_long",
            f"Email must be at most {MAX_EMAIL_LENGTH} characters",
        )
    
    if not EMAIL_REGEX.match(value):
        raise PydanticCustomError(
            "invalid_email",
            "Invalid email format",
        )
    
    return value


OSINTEmail = Annotated[str, AfterValidator(validate_email)]


# =============================================================================
# Domain Validator
# =============================================================================

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
MAX_DOMAIN_LENGTH = 253


def validate_domain(value: str) -> str:
    """
    Validate and normalize domain.
    - Punycode normalized
    - No scheme (http://)
    - No path/query
    - Lowercase
    """
    value = value.strip().lower()
    
    # Remove scheme if present
    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]
    
    # Remove path/query if present
    value = value.split("/")[0].split("?")[0].split("#")[0]
    
    # Remove port if present
    value = value.split(":")[0]
    
    if len(value) > MAX_DOMAIN_LENGTH:
        raise PydanticCustomError(
            "domain_too_long",
            f"Domain must be at most {MAX_DOMAIN_LENGTH} characters",
        )
    
    # Handle punycode (internationalized domain names)
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        raise PydanticCustomError(
            "invalid_domain_encoding",
            "Invalid domain encoding",
        )
    
    if not DOMAIN_REGEX.match(value):
        raise PydanticCustomError(
            "invalid_domain",
            "Invalid domain format",
        )
    
    return value


OSINTDomain = Annotated[str, AfterValidator(validate_domain)]


# =============================================================================
# Username Validator
# =============================================================================

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")


def validate_username(value: str) -> str:
    """
    Validate username for OSINT lookups.
    - Alphanumeric + . _ -
    - 3-32 characters
    - Trimmed
    """
    value = value.strip()
    
    if not USERNAME_REGEX.match(value):
        raise PydanticCustomError(
            "invalid_username",
            "Username must be 3-32 characters, alphanumeric with . _ - allowed",
        )
    
    return value


OSINTUsername = Annotated[str, AfterValidator(validate_username)]


# =============================================================================
# IP Address Validator
# =============================================================================

IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
IPV6_REGEX = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$")


def validate_ip_address(value: str) -> str:
    """Validate IP address (v4 or v6)."""
    value = value.strip()
    
    if not (IPV4_REGEX.match(value) or IPV6_REGEX.match(value)):
        raise PydanticCustomError(
            "invalid_ip",
            "Invalid IP address format",
        )
    
    return value


OSINTIPAddress = Annotated[str, AfterValidator(validate_ip_address)]

