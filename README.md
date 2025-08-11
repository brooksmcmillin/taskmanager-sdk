# TaskManager SDK

A Python SDK for interacting with the TaskManager API. This library provides a clean, Pythonic interface for all TaskManager functionality including authentication, project management, todo management, reporting, and OAuth.

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
    tags=["documentation", "high-priority"],
    context="work"
)

if new_todo.success:
    todo_id = new_todo.data['id']
    print(f"Created todo with ID: {todo_id}")

# Complete a todo
completion = client.complete_todo(todo_id, actual_hours=3.5)
if completion.success:
    print("Todo completed successfully!")
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
- `get_current_user()` - Get current user information

#### Project Methods

- `get_projects()` - Get all projects
- `create_project(name, color, description=None)` - Create a new project
- `get_project(project_id)` - Get a specific project
- `update_project(project_id, name=None, color=None, description=None)` - Update a project

#### Todo Methods

- `get_todos(project_id=None, status=None, time_horizon=None)` - Get todos with filters
- `create_todo(title, ...)` - Create a new todo
- `get_todo(todo_id)` - Get a specific todo
- `update_todo(todo_id, ...)` - Update a todo
- `complete_todo(todo_id, actual_hours)` - Mark a todo as completed

#### Reporting Methods

- `get_reports(start_date, end_date, status="pending", time_horizon=None)` - Get reports

#### OAuth Methods

- `get_oauth_clients()` - Get OAuth clients
- `create_oauth_client(name, redirect_uris, ...)` - Create OAuth client
- `oauth_token_exchange(grant_type, client_id, client_secret, ...)` - Exchange tokens

## Models

The SDK includes data models for API responses:

- `ApiResponse` - Standard API response wrapper
- `User` - User account information
- `Project` - Project details
- `Todo` - Todo item details
- `OAuthClient` - OAuth client information

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