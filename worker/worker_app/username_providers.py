"""
Username OSINT Providers - GitHub and Reddit.

Provider abstraction for username lookups across social platforms.
Implements rate limiting, evidence collection, and normalization.
"""
import httpx
import time
import json
import hashlib
from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger()


# =============================================================================
# Base Provider
# =============================================================================

class UsernameProvider(ABC):
    """Abstract base class for username lookup providers."""
    
    @property
    @abstractmethod
    def platform(self) -> str:
        """Platform identifier (github, reddit, etc)."""
        pass
    
    @abstractmethod
    def lookup(self, username: str) -> dict:
        """
        Lookup username on the platform.
        
        Returns:
        {
            "success": True/False,
            "exists": True/False/None,
            "status_code": int,
            "headers": dict,
            "body": dict or None,
            "error": str or None,
            "fetched_at": ISO timestamp,
        }
        """
        pass
    
    @abstractmethod
    def normalize(self, username: str, response: dict) -> list[dict]:
        """
        Normalize response to findings.
        
        Returns list of finding dicts.
        """
        pass


# =============================================================================
# GitHub Provider
# =============================================================================

class GitHubProvider(UsernameProvider):
    """
    GitHub username lookup provider.
    
    Rate limits:
    - Without token: 60 requests/hour
    - With token: 5000 requests/hour
    
    API: https://api.github.com/users/{username}
    """
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None, timeout: float = 10.0):
        self.token = token
        self.timeout = timeout
        self._headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OSINT-Platform/1.0 (security research)",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
    
    @property
    def platform(self) -> str:
        return "github"
    
    def lookup(self, username: str) -> dict:
        """Query GitHub API for user profile."""
        endpoint = f"/users/{username}"
        url = f"{self.BASE_URL}{endpoint}"
        fetched_at = datetime.now(timezone.utc).isoformat()
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, headers=self._headers)
                
                result = {
                    "success": True,
                    "exists": response.status_code == 200,
                    "status_code": response.status_code,
                    "headers": {
                        "x-ratelimit-limit": response.headers.get("x-ratelimit-limit"),
                        "x-ratelimit-remaining": response.headers.get("x-ratelimit-remaining"),
                        "x-ratelimit-reset": response.headers.get("x-ratelimit-reset"),
                    },
                    "body": response.json() if response.status_code == 200 else None,
                    "error": None,
                    "fetched_at": fetched_at,
                    "endpoint": endpoint,
                }
                
                # Handle rate limiting
                if response.status_code == 403:
                    remaining = response.headers.get("x-ratelimit-remaining", "0")
                    if remaining == "0":
                        result["error"] = "rate_limit_exceeded"
                        result["success"] = False
                
                # 404 is valid (user doesn't exist)
                if response.status_code == 404:
                    result["exists"] = False
                    result["body"] = {"message": "Not Found"}
                
                return result
                
        except httpx.TimeoutException:
            return {
                "success": False,
                "exists": None,
                "status_code": None,
                "headers": {},
                "body": None,
                "error": "timeout",
                "fetched_at": fetched_at,
                "endpoint": endpoint,
            }
        except Exception as e:
            return {
                "success": False,
                "exists": None,
                "status_code": None,
                "headers": {},
                "body": None,
                "error": str(e),
                "fetched_at": fetched_at,
                "endpoint": endpoint,
            }
    
    def normalize(self, username: str, response: dict) -> list[dict]:
        """Normalize GitHub response to findings."""
        findings = []
        
        if not response.get("success"):
            return findings
        
        body = response.get("body", {})
        exists = response.get("exists", False)
        
        # Calculate confidence
        base_confidence = 70 if exists else 50
        
        # Boost confidence for active users
        if exists and body:
            updated_at = body.get("updated_at")
            if updated_at:
                try:
                    updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    months_ago = (datetime.now(timezone.utc) - updated).days / 30
                    if months_ago < 12:
                        base_confidence += 10
                except:
                    pass
            
            # Boost for activity signals
            repos = body.get("public_repos", 0)
            followers = body.get("followers", 0)
            if repos > 5 or followers > 10:
                base_confidence += 5
        
        # Clamp confidence
        base_confidence = min(95, base_confidence)
        
        # USERNAME_IDENTITY finding
        identity_data = {
            "platform": "github",
            "exists": exists,
            "profile_url": f"https://github.com/{username}" if exists else None,
        }
        
        if exists and body:
            identity_data.update({
                "user_id": body.get("id"),
                "login": body.get("login"),
                "name": body.get("name"),
                "bio": body.get("bio"),
                "location": body.get("location"),
                "blog": body.get("blog"),
                "company": body.get("company"),
                "public_repos": body.get("public_repos"),
                "followers": body.get("followers"),
                "following": body.get("following"),
                "created_at": body.get("created_at"),
            })
        
        findings.append({
            "finding_type": "USERNAME_IDENTITY",
            "subject": username,
            "confidence": base_confidence,
            "data": identity_data,
        })
        
        # USERNAME_ACTIVITY finding (if exists and has activity)
        if exists and body:
            repos = body.get("public_repos", 0)
            if repos > 0:
                findings.append({
                    "finding_type": "USERNAME_ACTIVITY",
                    "subject": username,
                    "confidence": base_confidence - 10,
                    "data": {
                        "platform": "github",
                        "metric": "public_repos",
                        "value": repos,
                    },
                })
            
            followers = body.get("followers", 0)
            if followers > 0:
                findings.append({
                    "finding_type": "USERNAME_ACTIVITY",
                    "subject": username,
                    "confidence": base_confidence - 10,
                    "data": {
                        "platform": "github",
                        "metric": "followers",
                        "value": followers,
                    },
                })
        
        return findings


# =============================================================================
# Reddit Provider
# =============================================================================

class RedditProvider(UsernameProvider):
    """
    Reddit username lookup provider.
    
    Rate limits:
    - ~1 request per 2-3 seconds per IP
    - Requires proper User-Agent (Reddit blocks generic)
    
    API: https://www.reddit.com/user/{username}/about.json
    """
    
    BASE_URL = "https://www.reddit.com"
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._headers = {
            "Accept": "application/json",
            # Reddit requires a descriptive User-Agent
            "User-Agent": "OSINT-Platform/1.0 (security research; contact: admin@example.com)",
        }
    
    @property
    def platform(self) -> str:
        return "reddit"
    
    def lookup(self, username: str) -> dict:
        """Query Reddit API for user profile."""
        endpoint = f"/user/{username}/about.json"
        url = f"{self.BASE_URL}{endpoint}"
        fetched_at = datetime.now(timezone.utc).isoformat()
        
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url, headers=self._headers)
                
                result = {
                    "success": True,
                    "exists": response.status_code == 200,
                    "status_code": response.status_code,
                    "headers": {
                        "x-ratelimit-remaining": response.headers.get("x-ratelimit-remaining"),
                        "x-ratelimit-reset": response.headers.get("x-ratelimit-reset"),
                    },
                    "body": None,
                    "error": None,
                    "fetched_at": fetched_at,
                    "endpoint": endpoint,
                }
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Reddit returns {"kind": "t2", "data": {...}}
                        result["body"] = data.get("data", data)
                    except:
                        result["body"] = None
                        result["error"] = "invalid_json"
                
                # 404 = user doesn't exist
                if response.status_code == 404:
                    result["exists"] = False
                    result["body"] = {"message": "Not Found"}
                
                # Rate limited
                if response.status_code == 429:
                    result["error"] = "rate_limit_exceeded"
                    result["success"] = False
                
                # Forbidden (often means suspended)
                if response.status_code == 403:
                    result["exists"] = True  # Account exists but is suspended
                    result["body"] = {"message": "Forbidden", "suspended": True}
                
                return result
                
        except httpx.TimeoutException:
            return {
                "success": False,
                "exists": None,
                "status_code": None,
                "headers": {},
                "body": None,
                "error": "timeout",
                "fetched_at": fetched_at,
                "endpoint": endpoint,
            }
        except Exception as e:
            return {
                "success": False,
                "exists": None,
                "status_code": None,
                "headers": {},
                "body": None,
                "error": str(e),
                "fetched_at": fetched_at,
                "endpoint": endpoint,
            }
    
    def normalize(self, username: str, response: dict) -> list[dict]:
        """Normalize Reddit response to findings."""
        findings = []
        
        if not response.get("success"):
            return findings
        
        body = response.get("body", {})
        exists = response.get("exists", False)
        
        # Calculate confidence
        base_confidence = 65 if exists else 50
        
        # Boost for active users
        if exists and body:
            created_utc = body.get("created_utc")
            if created_utc:
                try:
                    created = datetime.fromtimestamp(created_utc, tz=timezone.utc)
                    account_age_years = (datetime.now(timezone.utc) - created).days / 365
                    if account_age_years > 1:
                        base_confidence += 5
                except:
                    pass
            
            # Karma indicates activity
            link_karma = body.get("link_karma", 0)
            comment_karma = body.get("comment_karma", 0)
            total_karma = link_karma + comment_karma
            if total_karma > 100:
                base_confidence += 10
        
        # Clamp confidence
        base_confidence = min(90, base_confidence)
        
        # USERNAME_IDENTITY finding
        identity_data = {
            "platform": "reddit",
            "exists": exists,
            "profile_url": f"https://www.reddit.com/user/{username}" if exists else None,
        }
        
        if exists and body:
            # Convert created_utc to ISO format
            created_at = None
            created_utc = body.get("created_utc")
            if created_utc:
                try:
                    created_at = datetime.fromtimestamp(created_utc, tz=timezone.utc).isoformat()
                except:
                    pass
            
            identity_data.update({
                "user_id": body.get("id"),
                "name": body.get("name"),
                "link_karma": body.get("link_karma"),
                "comment_karma": body.get("comment_karma"),
                "is_employee": body.get("is_employee"),
                "is_gold": body.get("is_gold"),
                "is_mod": body.get("is_mod"),
                "has_verified_email": body.get("has_verified_email"),
                "created_at": created_at,
                "suspended": body.get("suspended", False),
            })
        
        findings.append({
            "finding_type": "USERNAME_IDENTITY",
            "subject": username,
            "confidence": base_confidence,
            "data": identity_data,
        })
        
        # USERNAME_ACTIVITY findings (karma metrics)
        if exists and body:
            link_karma = body.get("link_karma", 0)
            if link_karma > 0:
                findings.append({
                    "finding_type": "USERNAME_ACTIVITY",
                    "subject": username,
                    "confidence": base_confidence - 5,
                    "data": {
                        "platform": "reddit",
                        "metric": "link_karma",
                        "value": link_karma,
                    },
                })
            
            comment_karma = body.get("comment_karma", 0)
            if comment_karma > 0:
                findings.append({
                    "finding_type": "USERNAME_ACTIVITY",
                    "subject": username,
                    "confidence": base_confidence - 5,
                    "data": {
                        "platform": "reddit",
                        "metric": "comment_karma",
                        "value": comment_karma,
                    },
                })
        
        return findings


# =============================================================================
# Mock Provider (for testing)
# =============================================================================

class MockUsernameProvider(UsernameProvider):
    """Mock provider for testing."""
    
    def __init__(self, platform_name: str = "mock"):
        self._platform = platform_name
        self._responses = {}
    
    @property
    def platform(self) -> str:
        return self._platform
    
    def set_response(self, username: str, response: dict):
        """Set mock response for a username."""
        self._responses[username] = response
    
    def lookup(self, username: str) -> dict:
        if username in self._responses:
            return self._responses[username]
        
        # Default mock response
        return {
            "success": True,
            "exists": True,
            "status_code": 200,
            "headers": {},
            "body": {
                "id": 12345,
                "login": username,
                "name": f"Mock User {username}",
                "_mock": True,
            },
            "error": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "endpoint": f"/users/{username}",
        }
    
    def normalize(self, username: str, response: dict) -> list[dict]:
        exists = response.get("exists", False)
        return [{
            "finding_type": "USERNAME_IDENTITY",
            "subject": username,
            "confidence": 50,
            "data": {
                "platform": self._platform,
                "exists": exists,
                "profile_url": f"https://{self._platform}.example.com/{username}",
                "_mock": True,
            },
        }]


# =============================================================================
# Provider Registry
# =============================================================================

def get_provider(platform: str, **kwargs) -> UsernameProvider:
    """Get provider instance for a platform."""
    providers = {
        "github": GitHubProvider,
        "reddit": RedditProvider,
        "mock": MockUsernameProvider,
    }
    
    provider_class = providers.get(platform.lower())
    if not provider_class:
        raise ValueError(f"Unknown platform: {platform}")
    
    return provider_class(**kwargs)


def username_lookup(username: str, platform: str, **kwargs) -> dict:
    """
    Perform username lookup on specified platform.
    
    Returns:
    {
        "success": True/False,
        "platform": str,
        "username": str,
        "response": {...},
        "findings": [...],
    }
    """
    provider = get_provider(platform, **kwargs)
    response = provider.lookup(username)
    findings = provider.normalize(username, response)
    
    return {
        "success": response.get("success", False),
        "platform": platform,
        "username": username,
        "response": response,
        "findings": findings,
    }

