"""
Worker configuration with production safety validation.
"""
import os
import sys
from pydantic_settings import BaseSettings
from pydantic import field_validator


DEFAULT_ENABLED_TECHNIQUES = frozenset([
    "domain_dns_lookup",
    "domain_whois_rdap_lookup",
    "cert_transparency",
    "subdomain_enum",
    "username_github_lookup",
    "username_reddit_lookup",
    "email_mx_spf_dmarc_correlation",
    "email_breach_lookup",
])

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
    ENV: str = os.getenv("ENV", "local")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # MinIO
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "minio:9000")
    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minio")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minio123456")
    MINIO_BUCKET: str = os.getenv("MINIO_BUCKET", "evidence")
    MINIO_SECURE: bool = os.getenv("MINIO_SECURE", "false").lower() == "true"

    # Optional JWT (if ever needed by worker)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")

    # Techniques
    ENABLED_TECHNIQUES: frozenset[str] = DEFAULT_ENABLED_TECHNIQUES

    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def is_production(self) -> bool:
        return self.ENV.lower() == "prod"

    @field_validator("ENABLED_TECHNIQUES", mode="before")
    @classmethod
    def _parse_enabled_techniques(cls, value):
        if value is None or value == "":
            return DEFAULT_ENABLED_TECHNIQUES
        if isinstance(value, (set, frozenset, list, tuple)):
            return frozenset(value)
        if isinstance(value, str):
            items = [v.strip() for v in value.split(",") if v.strip()]
            return frozenset(items) if items else DEFAULT_ENABLED_TECHNIQUES
        return DEFAULT_ENABLED_TECHNIQUES

    def validate_production_safety(self) -> list[str]:
        errors = []

        if not self.is_production:
            return errors

        # Debug must be false
        if self.DEBUG:
            errors.append(
                "SECURITY ERROR: DEBUG=true in production. Set DEBUG=false for production."
            )

        # MinIO default credentials
        if self.MINIO_ACCESS_KEY == "minio" and self.MINIO_SECRET_KEY == "minio123456":
            errors.append(
                "SECURITY WARNING: MinIO using default credentials. Set MINIO_ACCESS_KEY and MINIO_SECRET_KEY."
            )

        # Optional JWT validation if provided
        if self.JWT_SECRET_KEY:
            if self.JWT_SECRET_KEY in DANGEROUS_DEFAULTS["JWT_SECRET_KEY"]:
                errors.append(
                    "SECURITY ERROR: JWT_SECRET_KEY is using a dangerous default. Set a secure random value."
                )
            if len(self.JWT_SECRET_KEY) < 32:
                errors.append(
                    f"SECURITY ERROR: JWT_SECRET_KEY is too short ({len(self.JWT_SECRET_KEY)} chars). Minimum 32 characters required."
                )

        return errors


def check_production_safety() -> None:
    settings = Settings()
    errors = settings.validate_production_safety()

    if errors:
        print("\n" + "=" * 60, file=sys.stderr)
        print("🚨 WORKER PRODUCTION SAFETY CHECK FAILED", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for error in errors:
            print(f"\n❌ {error}", file=sys.stderr)
        print("\n" + "=" * 60, file=sys.stderr)
        print("Fix the above issues or set ENV=local for development.", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        sys.exit(1)

    if settings.is_production:
        print("✅ Worker production safety check passed", file=sys.stderr)


settings = Settings()
