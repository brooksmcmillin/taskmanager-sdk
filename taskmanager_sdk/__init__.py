"""
TaskManager SDK - Python client library for TaskManager API.

This SDK provides a clean, Pythonic interface for interacting with the TaskManager API,
including authentication, project management, todo management, reporting, and OAuth functionality.

Basic usage:
    >>> from taskmanager_sdk import TaskManagerClient, create_authenticated_client
    >>> 
    >>> # Method 1: Create client and authenticate manually
    >>> client = TaskManagerClient("http://localhost:4321/api")
    >>> response = client.login("username", "password")
    >>> 
    >>> # Method 2: Create pre-authenticated client
    >>> client = create_authenticated_client("username", "password")
    >>> 
    >>> # Use the client
    >>> projects = client.get_projects()
    >>> todos = client.get_todos()
"""

__version__ = "0.1.1"
__author__ = "TaskManager SDK"

from .client import TaskManagerClient, create_authenticated_client
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TaskManagerError,
    ValidationError,
)
from .models import (
    ApiResponse,
    OAuthClient,
    OAuthError,
    OAuthToken,
    Project,
    Todo,
    User,
)

__all__ = [
    # Client classes
    "TaskManagerClient",
    "create_authenticated_client",
    # Models
    "ApiResponse",
    "User", 
    "Project",
    "Todo",
    "OAuthClient",
    "OAuthToken",
    "OAuthError",
    # Exceptions
    "TaskManagerError",
    "AuthenticationError", 
    "AuthorizationError",
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
]
