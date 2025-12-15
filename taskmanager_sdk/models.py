from dataclasses import dataclass
from typing import Any


@dataclass
class ApiResponse:
    """Response object for all API calls."""
    success: bool
    data: Any | None = None
    error: str | None = None
    status_code: int | None = None


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
    description: str | None
    created_at: str
    updated_at: str
    user_id: int


@dataclass
class Todo:
    """Todo model."""
    id: int
    title: str
    description: str | None
    priority: str
    estimated_hours: float
    actual_hours: float | None
    status: str
    due_date: str | None
    tags: list[str] | None
    created_at: str
    updated_at: str
    completed_at: str | None
    user_id: int
    project_id: int | None


@dataclass
class OAuthClient:
    """OAuth client model."""
    id: int
    name: str
    client_id: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    is_active: bool
    created_at: str


@dataclass
class OAuthToken:
    """OAuth token response model."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None


@dataclass
class OAuthError:
    """OAuth error response model."""
    error: str
    error_description: str | None = None