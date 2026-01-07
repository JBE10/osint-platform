"""
Application configuration with security validation.

SECURITY: In production (ENV=prod), dangerous defaults will cause
the application to fail fast at startup.
"""
import os
import sys
from enum import Enum

from pydantic_settings import BaseSettings


class Environment(str, Enum):
    """Application environment."""
    LOCAL = "local"
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


# =============================================================================
# V1 Enabled Techniques (config-driven allowlist)
# =============================================================================
DEFAULT_ENABLED_TECHNIQUES = frozenset([
    "domain_dns_lookup",
    "domain_whois_rdap_lookup",
    "username_github_lookup",
    "username_reddit_lookup",
    "email_mx_spf_dmarc_correlation",
    "email_breach_lookup",
])

# Techniques that exist but are disabled in V1
DISABLED_TECHNIQUES = frozenset([
    "subdomain_enum",
    "cert_transparency",
    "email_verify",
    "port_scan",
    "screenshot",
    "social_lookup",
    "breach_check",
    "dns_lookup",      # Legacy alias
    "whois_lookup",    # Legacy alias
    "noop_lookup",     # Testing only - disable in prod
])


# =============================================================================
# Dangerous defaults that must NOT be used in production
# =============================================================================
DANGEROUS_DEFAULTS = {
    "JWT_SECRET_KEY": [
        "change-me-in-production-use-openssl-rand-hex-32",
        "change-me",
        "secret",
        "jwt-secret",
        "supersecret",
    ],
}


class Settings(BaseSettings):
    """
    Application settings with production safety checks.
    
    Usage:
        from app.core.config import settings
        
    Security:
        - Set ENV=prod in production
        - Fail-fast if dangerous defaults are detected in prod
    """
    
    # ==========================================================================
    # Environment
    # ==========================================================================
    ENV: str = os.getenv("ENV", "local")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # ==========================================================================
    # V1 Enabled Techniques (allowlist)
    # ==========================================================================
    # Can be overridden via env: ENABLED_TECHNIQUES=domain_dns_lookup,domain_whois_rdap_lookup
    ENABLED_TECHNIQUES: frozenset[str] = DEFAULT_ENABLED_TECHNIQUES
    
    # ==========================================================================
    # Database
    # ==========================================================================
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql+psycopg://osint:osint@localhost:5432/osint"
    )
    
    # ==========================================================================
    # Redis
    # ==========================================================================
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # ==========================================================================
    # JWT (SECURITY CRITICAL)
    # ==========================================================================
    JWT_SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY", 
        "change-me-in-production-use-openssl-rand-hex-32"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # ==========================================================================
    # Rate Limiting (requests per minute)
    # ==========================================================================
    RATE_LIMIT_AUTH: int = 5      # Login/register attempts
    RATE_LIMIT_READ: int = 120    # GET requests
    RATE_LIMIT_MUTATE: int = 30   # POST/PUT/DELETE requests
    
    # ==========================================================================
    # MinIO
    # ==========================================================================
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minio")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minio123456")
    
    # ==========================================================================
    # Celery
    # ==========================================================================
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

    class Config:
        env_file = ".env"
        case_sensitive = True
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.ENV.lower() == "prod"
    
    @property
    def is_local(self) -> bool:
        """Check if running locally."""
        return self.ENV.lower() in ("local", "dev")
    
    def is_technique_enabled(self, technique_code: str) -> bool:
        """Check if a technique is enabled."""
        return technique_code in self.ENABLED_TECHNIQUES
    
    def validate_production_safety(self) -> list[str]:
        """
        Validate that no dangerous defaults are used in production.
        
        Returns list of validation errors (empty if all OK).
        """
        errors = []
        
        if not self.is_production:
            return errors
        
        # Check JWT secret
        if self.JWT_SECRET_KEY in DANGEROUS_DEFAULTS["JWT_SECRET_KEY"]:
            errors.append(
                "SECURITY ERROR: JWT_SECRET_KEY is using a dangerous default. "
                "Set a secure random value: openssl rand -hex 32"
            )
        
        # Check JWT secret length (minimum 32 chars)
        if len(self.JWT_SECRET_KEY) < 32:
            errors.append(
                f"SECURITY ERROR: JWT_SECRET_KEY is too short ({len(self.JWT_SECRET_KEY)} chars). "
                "Minimum 32 characters required."
            )
        
        # Check debug mode
        if self.DEBUG:
            errors.append(
                "SECURITY ERROR: DEBUG=true in production. "
                "Set DEBUG=false for production."
            )
        
        # Check MinIO credentials
        if self.MINIO_ACCESS_KEY == "minio" and self.MINIO_SECRET_KEY == "minio123456":
            errors.append(
                "SECURITY WARNING: MinIO using default credentials. "
                "Set MINIO_ACCESS_KEY and MINIO_SECRET_KEY."
            )
        
        # Check noop_lookup is disabled in prod
        if "noop_lookup" in self.ENABLED_TECHNIQUES:
            errors.append(
                "SECURITY WARNING: noop_lookup is enabled in production. "
                "Remove it from ENABLED_TECHNIQUES."
            )
        
        return errors


# =============================================================================
# Create settings instance
# =============================================================================
settings = Settings()


# =============================================================================
# Production safety check (fail fast)
# =============================================================================
def check_production_safety() -> None:
    """
    Check production safety at startup.
    
    Called from main.py to fail fast if misconfigured.
    """
    errors = settings.validate_production_safety()
    
    if errors:
        print("\n" + "=" * 60, file=sys.stderr)
        print("🚨 PRODUCTION SAFETY CHECK FAILED", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for error in errors:
            print(f"\n❌ {error}", file=sys.stderr)
        print("\n" + "=" * 60, file=sys.stderr)
        print("Fix the above issues or set ENV=local for development.", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        sys.exit(1)
    
    if settings.is_production:
        print("✅ Production safety check passed", file=sys.stderr)


# =============================================================================
# Helper for technique validation
# =============================================================================
def validate_technique(technique_code: str) -> None:
    """
    Validate that a technique is enabled.
    
    Raises ValueError if technique is disabled.
    """
    if not settings.is_technique_enabled(technique_code):
        raise ValueError(
            f"Technique '{technique_code}' is not enabled. "
            f"Enabled: {sorted(settings.ENABLED_TECHNIQUES)}"
        )
