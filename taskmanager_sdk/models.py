from dataclasses import dataclass
from typing import Any, Optional


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
    created_at: str
    updated_at: str


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
    tags: Optional[list[str]]
    context: str
    time_horizon: Optional[str]
    created_at: str
    updated_at: str
    user_id: int
    project_id: Optional[int]


@dataclass
class OAuthClient:
    """OAuth client model."""
    id: int
    name: str
    client_id: str
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    created_at: str
    user_id: int