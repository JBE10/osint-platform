"""ID generation utilities for OSINT Platform.

Provides consistent, prefixed ID generation across all services.
Uses ULID-like format for sortable, unique identifiers.
"""

import secrets
import time
from typing import Literal

# Prefix mapping for different entity types
ID_PREFIXES = {
    "workspace": "ws",
    "investigation": "inv",
    "target": "tgt",
    "job": "job",
    "artifact": "art",
    "user": "usr",
    "audit": "aud",
}

EntityType = Literal[
    "workspace",
    "investigation", 
    "target",
    "job",
    "artifact",
    "user",
    "audit",
]


def generate_id(length: int = 22) -> str:
    """Generate a random URL-safe ID.
    
    Args:
        length: Length of the generated ID (default: 22)
        
    Returns:
        A URL-safe random string
    """
    return secrets.token_urlsafe(length)[:length]


def generate_prefixed_id(entity_type: EntityType) -> str:
    """Generate a prefixed ID for a specific entity type.
    
    Format: {prefix}_{timestamp_hex}_{random}
    
    The timestamp component ensures IDs are roughly sortable by creation time.
    
    Args:
        entity_type: Type of entity to generate ID for
        
    Returns:
        A prefixed, sortable unique identifier
        
    Example:
        >>> generate_prefixed_id("workspace")
        'ws_018d4f8a_xK9mN2pQ'
    """
    prefix = ID_PREFIXES[entity_type]
    
    # Timestamp in milliseconds, encoded as hex (first 8 chars)
    timestamp_hex = format(int(time.time() * 1000), 'x')[:8]
    
    # Random component for uniqueness
    random_part = secrets.token_urlsafe(8)[:8]
    
    return f"{prefix}_{timestamp_hex}_{random_part}"


def extract_prefix(entity_id: str) -> str | None:
    """Extract the prefix from a prefixed ID.
    
    Args:
        entity_id: The full entity ID
        
    Returns:
        The prefix if found, None otherwise
    """
    if "_" in entity_id:
        return entity_id.split("_")[0]
    return None


def validate_prefixed_id(entity_id: str, expected_type: EntityType) -> bool:
    """Validate that an ID has the correct prefix for its entity type.
    
    Args:
        entity_id: The ID to validate
        expected_type: The expected entity type
        
    Returns:
        True if the ID has the correct prefix, False otherwise
    """
    expected_prefix = ID_PREFIXES.get(expected_type)
    if not expected_prefix:
        return False
    
    return entity_id.startswith(f"{expected_prefix}_")

