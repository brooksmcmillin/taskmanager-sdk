# TaskManager SDK

A Python SDK for interacting with the TaskManager API. This library provides a clean, Pythonic interface for all TaskManager functionality including authentication, project management, todo management, and OAuth 2.0 authorization.

## Installation

```bash
pip install taskmanager-sdk
```

## Quick Start

### Basic Usage

```python
from taskmanager_sdk import TaskManagerClient, create_authenticated_client

# Method 1: Manual authentication
client = TaskManagerClient("http://localhost:4321/api")
response = client.login("your_username", "your_password")

if response.success:
    print("Authenticated successfully!")
else:
    print(f"Authentication failed: {response.error}")

# Method 2: Create pre-authenticated client (recommended)
try:
    client = create_authenticated_client("your_username", "your_password")
    print("Authenticated successfully!")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
```

### Working with Projects

```python
# Get all projects
projects = client.get_projects()
if projects.success:
    for project in projects.data:
        print(f"Project: {project['name']} ({project['color']})")

# Create a new project
new_project = client.create_project(
    name="My New Project",
    color="#FF5722",
    description="A project for important tasks"
)

if new_project.success:
    project_id = new_project.data['id']
    print(f"Created project with ID: {project_id}")
```

### Working with Todos

```python
# Get all todos
todos = client.get_todos()
if todos.success:
    for todo in todos.data:
        print(f"Todo: {todo['title']} (Status: {todo['status']})")

# Create a new todo
new_todo = client.create_todo(
    title="Complete the documentation",
    description="Write comprehensive docs for the new feature",
    priority="high",
    estimated_hours=4.0,
    due_date="2024-12-31T23:59:59Z",
    tags=["documentation", "high-priority"]
)

if new_todo.success:
    todo_id = new_todo.data['id']
    print(f"Created todo with ID: {todo_id}")

# Complete a todo
completion = client.complete_todo(todo_id, actual_hours=3.5)
if completion.success:
    print("Todo completed successfully!")
```

### OAuth 2.0 Authorization

The SDK supports OAuth 2.0 authorization flows for third-party integrations:

```python
# Create an OAuth client
oauth_client = client.create_oauth_client(
    name="My App",
    redirect_uris=["https://myapp.com/callback"],
    grant_types=["authorization_code"],
    scopes=["read", "write"]
)

if oauth_client.success:
    client_id = oauth_client.data['client_id']
    client_secret = oauth_client.data['client_secret']
    print(f"Created OAuth client: {client_id}")

# Get authorization URL (redirect user to this URL)
auth_response = client.oauth_authorize(
    client_id=client_id,
    redirect_uri="https://myapp.com/callback",
    scope="read",
    state="random_state_value"
)

# Exchange authorization code for tokens (after user authorizes)
token_response = client.oauth_token(
    grant_type="authorization_code",
    client_id=client_id,
    client_secret=client_secret,
    code="authorization_code_from_callback",
    redirect_uri="https://myapp.com/callback"
)

if token_response.success:
    access_token = token_response.data['access_token']
    refresh_token = token_response.data['refresh_token']
    print(f"Got access token: {access_token}")

# Get JWKS for token verification
jwks = client.get_jwks()
if jwks.success:
    print("JWKS:", jwks.data)
```

### Error Handling

The SDK provides specific exception types for different error conditions:

```python
from taskmanager_sdk import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    NetworkError
)

try:
    # API calls that might fail
    client = create_authenticated_client("invalid", "credentials")
except AuthenticationError:
    print("Invalid credentials provided")
except NetworkError:
    print("Could not connect to the server")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## API Reference

### TaskManagerClient

The main client class for interacting with the TaskManager API.

#### Constructor

```python
TaskManagerClient(base_url="http://localhost:4321/api", session=None)
```

- `base_url`: Base URL of the TaskManager API
- `session`: Optional requests.Session object for custom HTTP handling

#### Authentication Methods

- `login(username, password)` - Authenticate with username/password
- `register(username, email, password)` - Register a new user account
- `logout()` - Log out the current session

#### Project Methods

- `get_projects()` - Get all projects
- `create_project(name, color, description=None)` - Create a new project
- `get_project(project_id)` - Get a specific project
- `update_project(project_id, name=None, color=None, description=None)` - Update a project
- `delete_project(project_id)` - Delete a project

#### Todo Methods

- `get_todos(project_id=None, status=None, due_date=None)` - Get todos with filters
- `create_todo(title, project_id=None, description=None, priority="medium", estimated_hours=None, due_date=None, tags=None)` - Create a new todo
- `get_todo(todo_id)` - Get a specific todo
- `update_todo(todo_id, title=None, description=None, priority=None, estimated_hours=None, actual_hours=None, status=None, due_date=None, tags=None)` - Update a todo
- `delete_todo(todo_id)` - Delete a todo
- `complete_todo(todo_id, actual_hours)` - Mark a todo as completed

#### OAuth 2.0 Methods

- `get_oauth_clients()` - Get OAuth clients for the authenticated user
- `create_oauth_client(name, redirect_uris, grant_types=None, scopes=None)` - Create a new OAuth client
- `get_jwks()` - Get JSON Web Key Set for token verification
- `oauth_authorize(client_id, redirect_uri, response_type="code", scope=None, state=None, code_challenge=None, code_challenge_method=None)` - OAuth authorization endpoint
- `oauth_consent(client_id, redirect_uri, action, scope=None, state=None, code_challenge=None, code_challenge_method=None)` - Handle OAuth consent
- `oauth_token(grant_type, client_id, client_secret, code=None, redirect_uri=None, code_verifier=None, refresh_token=None)` - Exchange authorization codes for tokens

## Models

The SDK includes data models for API responses:

- `ApiResponse` - Standard API response wrapper
- `User` - User account information (id, username, email)
- `Project` - Project details (id, name, description, color, created_at, updated_at, user_id)
- `Todo` - Todo item details (id, title, description, priority, estimated_hours, actual_hours, status, due_date, tags, created_at, updated_at, completed_at, user_id, project_id)
- `OAuthClient` - OAuth client information (id, name, client_id, redirect_uris, grant_types, scopes, is_active, created_at)
- `OAuthToken` - OAuth token response (access_token, token_type, expires_in, refresh_token, scope)
- `OAuthError` - OAuth error response (error, error_description)

## Exception Hierarchy

- `TaskManagerError` - Base exception class
  - `AuthenticationError` - Authentication failures (401)
  - `AuthorizationError` - Authorization failures (403)
  - `NotFoundError` - Resource not found (404)
  - `ValidationError` - Request validation errors (400)
  - `RateLimitError` - Rate limit exceeded (429)
  - `ServerError` - Server errors (5xx)
  - `NetworkError` - Network/connection errors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

MIT License