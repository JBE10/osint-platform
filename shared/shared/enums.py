"""Enumerations shared across the OSINT Platform."""

from enum import Enum


class WorkspaceRole(str, Enum):
    """Roles within a workspace."""
    
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class InvestigationStatus(str, Enum):
    """Status of an investigation."""
    
    DRAFT = "draft"
    ACTIVE = "active"
    ON_HOLD = "on_hold"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class TargetType(str, Enum):
    """Types of investigation targets."""
    
    PERSON = "person"
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    CRYPTOCURRENCY = "cryptocurrency"
    VEHICLE = "vehicle"
    LOCATION = "location"
    DOCUMENT = "document"
    IMAGE = "image"
    OTHER = "other"


class JobStatus(str, Enum):
    """Status of a background job."""
    
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class JobType(str, Enum):
    """Types of OSINT jobs that can be executed."""
    
    # Domain Intelligence
    DNS_LOOKUP = "dns_lookup"
    WHOIS_LOOKUP = "whois_lookup"
    SUBDOMAIN_ENUM = "subdomain_enum"
    SSL_CERT_CHECK = "ssl_cert_check"
    
    # Network Intelligence
    PORT_SCAN = "port_scan"
    SHODAN_SEARCH = "shodan_search"
    IP_GEOLOCATION = "ip_geolocation"
    
    # Social Media
    SOCIAL_MEDIA_SEARCH = "social_media_search"
    USERNAME_SEARCH = "username_search"
    
    # Email Intelligence
    EMAIL_VERIFICATION = "email_verification"
    BREACH_CHECK = "breach_check"
    EMAIL_HEADERS_ANALYSIS = "email_headers_analysis"
    
    # Document & Image
    METADATA_EXTRACTION = "metadata_extraction"
    REVERSE_IMAGE_SEARCH = "reverse_image_search"
    
    # Web Intelligence
    WEBSITE_SCREENSHOT = "website_screenshot"
    WAYBACK_LOOKUP = "wayback_lookup"
    TECHNOLOGY_DETECTION = "technology_detection"
    
    # Custom
    CUSTOM_SCRIPT = "custom_script"


class AuditAction(str, Enum):
    """Actions that are logged in the audit trail."""
    
    # Workspace actions
    WORKSPACE_CREATED = "workspace_created"
    WORKSPACE_UPDATED = "workspace_updated"
    WORKSPACE_DELETED = "workspace_deleted"
    WORKSPACE_MEMBER_ADDED = "workspace_member_added"
    WORKSPACE_MEMBER_REMOVED = "workspace_member_removed"
    
    # Investigation actions
    INVESTIGATION_CREATED = "investigation_created"
    INVESTIGATION_UPDATED = "investigation_updated"
    INVESTIGATION_DELETED = "investigation_deleted"
    INVESTIGATION_STATUS_CHANGED = "investigation_status_changed"
    
    # Target actions
    TARGET_CREATED = "target_created"
    TARGET_UPDATED = "target_updated"
    TARGET_DELETED = "target_deleted"
    TARGET_LINKED = "target_linked"
    
    # Job actions
    JOB_CREATED = "job_created"
    JOB_STARTED = "job_started"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    JOB_CANCELLED = "job_cancelled"
    
    # Data actions
    DATA_EXPORTED = "data_exported"
    DATA_IMPORTED = "data_imported"
    ARTIFACT_UPLOADED = "artifact_uploaded"
    ARTIFACT_DOWNLOADED = "artifact_downloaded"

