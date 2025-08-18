from dataclasses import dataclass
from typing import Any, Optional, List


@dataclass
class ApiResponse:
    """Response object for all API calls."""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    status_code: Optional[int] = None


@dataclass
class User:
    """User model."""
    id: int
    username: str
    email: str


@dataclass
class Project:
    """Project model."""
    id: int
    name: str
    color: str
    description: Optional[str]
    created_at: str
    updated_at: str
    user_id: int


@dataclass
class Todo:
    """Todo model."""
    id: int
    title: str
    description: Optional[str]
    priority: str
    estimated_hours: float
    actual_hours: Optional[float]
    status: str
    due_date: Optional[str]
    tags: Optional[List[str]]
    created_at: str
    updated_at: str
    completed_at: Optional[str]
    user_id: int
    project_id: Optional[int]


@dataclass
class OAuthClient:
    """OAuth client model."""
    id: int
    name: str
    client_id: str
    redirect_uris: List[str]
    grant_types: List[str]
    scopes: List[str]
    is_active: bool
    created_at: str


@dataclass
class OAuthToken:
    """OAuth token response model."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


@dataclass
class OAuthError:
    """OAuth error response model."""
    error: str
    error_description: Optional[str] = None