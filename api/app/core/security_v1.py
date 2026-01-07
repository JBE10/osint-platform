"""
Security configuration for V1 - Audit policy.

This module defines which actions should be audited.
Technique allowlist is now in config.py (config-driven).
"""
import re


# =============================================================================
# Audit policy: which actions should be logged
# =============================================================================
AUDITED_ACTIONS = {
    # Auth
    "POST:/v1/auth/register": "auth.register",
    "POST:/v1/auth/login": "auth.login",
    
    # Workspaces
    "POST:/v1/workspaces": "workspace.create",
    "PUT:/v1/workspaces/{workspace_id}": "workspace.update",
    "DELETE:/v1/workspaces/{workspace_id}": "workspace.delete",
    
    # Targets
    "POST:/v1/workspaces/{workspace_id}/targets/domain": "target.create",
    "POST:/v1/workspaces/{workspace_id}/targets/email": "target.create",
    "POST:/v1/workspaces/{workspace_id}/targets/username": "target.create",
    
    # Jobs
    "POST:/v1/workspaces/{workspace_id}/jobs": "job.create",
    "POST:/v1/workspaces/{workspace_id}/jobs/{job_id}/enqueue": "job.enqueue",
    "POST:/v1/workspaces/{workspace_id}/jobs/{job_id}/requeue": "job.requeue",
    "POST:/v1/workspaces/{workspace_id}/jobs/{job_id}/cancel": "job.cancel",
    
    # Investigations
    "POST:/v1/workspaces/{workspace_id}/investigations": "investigation.create",
    "GET:/v1/workspaces/{workspace_id}/investigations/{investigation_id}/export": "investigation.export",
    
    # Findings export
    "GET:/v1/workspaces/{workspace_id}/findings/export/json": "findings.export",
}


def get_audit_action(method: str, path: str) -> str | None:
    """
    Get audit action for a request.
    
    Matches path patterns like /v1/workspaces/{id}/jobs to the action.
    Returns None if the action should not be audited.
    """
    # Normalize path
    normalized = path.rstrip("/")
    
    # Try exact match first
    key = f"{method}:{normalized}"
    if key in AUDITED_ACTIONS:
        return AUDITED_ACTIONS[key]
    
    # UUID pattern for path matching
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    
    # Check all patterns
    for pattern_key, action in AUDITED_ACTIONS.items():
        pattern_method, pattern_template = pattern_key.split(":", 1)
        if method != pattern_method:
            continue
        
        # Convert template to regex
        regex_pattern = pattern_template.replace("{workspace_id}", uuid_pattern)
        regex_pattern = regex_pattern.replace("{job_id}", uuid_pattern)
        regex_pattern = regex_pattern.replace("{investigation_id}", uuid_pattern)
        regex_pattern = regex_pattern.replace("{target_id}", uuid_pattern)
        regex_pattern = f"^{regex_pattern}$"
        
        if re.match(regex_pattern, normalized):
            return action
    
    return None
