from typing import Optional, Dict, Any, List

import requests

from .models import ApiResponse
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ServerError,
    NetworkError,
)


class TaskManagerClient:
    """
    Python SDK client for TaskManager API.
    
    Provides methods for interacting with all TaskManager endpoints including
    authentication, project management, todo management, reporting, and OAuth.
    """

    def __init__(
        self, 
        base_url: str = "http://localhost:4321/api", 
        session: Optional[requests.Session] = None
    ) -> None:
        """
        Initialize the TaskManager client.
        
        Args:
            base_url: Base URL for the TaskManager API
            session: Optional requests session to use for HTTP calls
        """
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.cookies: Dict[str, str] = {}

    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None, 
        params: Optional[Dict[str, Any]] = None
    ) -> ApiResponse:
        """
        Make HTTP request to the API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: JSON data for request body
            params: Query parameters
            
        Returns:
            ApiResponse object with success status, data, and error information
            
        Raises:
            NetworkError: For connection/network issues
            AuthenticationError: For 401 status codes
            AuthorizationError: For 403 status codes
            NotFoundError: For 404 status codes
            ValidationError: For 400 status codes
            RateLimitError: For 429 status codes
            ServerError: For 5xx status codes
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, cookies=self.cookies)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, cookies=self.cookies)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, params=params, cookies=self.cookies)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, params=params, cookies=self.cookies)
            else:
                return ApiResponse(success=False, error=f"Unsupported HTTP method: {method}")

            # Handle cookie authentication
            if 'set-cookie' in response.headers:
                split_cookie = response.headers["set-cookie"].split("=", 1)
                if len(split_cookie) == 2:
                    self.cookies[split_cookie[0]] = split_cookie[1].split(";")[0]
            
            # Handle error status codes with appropriate exceptions
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', f'HTTP {response.status_code}')
                except:
                    error_message = f'HTTP {response.status_code}: {response.text}'
                
                api_response = ApiResponse(
                    success=False, 
                    error=error_message, 
                    status_code=response.status_code
                )
                
                # Raise appropriate exception based on status code
                if response.status_code == 401:
                    raise AuthenticationError(error_message)
                elif response.status_code == 403:
                    raise AuthorizationError(error_message)
                elif response.status_code == 404:
                    raise NotFoundError(error_message)
                elif response.status_code == 400:
                    raise ValidationError(error_message)
                elif response.status_code == 429:
                    raise RateLimitError(error_message)
                elif response.status_code >= 500:
                    raise ServerError(error_message)
                
                return api_response
            
            # Parse JSON response
            try:
                json_data = response.json()
            except:
                json_data = None
            
            return ApiResponse(success=True, data=json_data, status_code=response.status_code)
            
        except requests.exceptions.RequestException as e:
            raise NetworkError(str(e))

    # Authentication methods
    def login(self, username: str, password: str) -> ApiResponse:
        """
        Authenticate user with username and password.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            ApiResponse with authentication result
        """
        return self._make_request('POST', '/auth/login', {
            'username': username,
            'password': password
        })

    def register(self, username: str, email: str, password: str) -> ApiResponse:
        """
        Register a new user account.
        
        Args:
            username: Desired username
            email: User's email address
            password: User's password
            
        Returns:
            ApiResponse with registration result
        """
        return self._make_request('POST', '/auth/register', {
            'username': username,
            'email': email,
            'password': password
        })

    def logout(self) -> ApiResponse:
        """
        Log out the current user session.
        
        Returns:
            ApiResponse with logout result
        """
        return self._make_request('POST', '/auth/logout')

    def get_current_user(self) -> ApiResponse:
        """
        Get current authenticated user information.
        
        Returns:
            ApiResponse with user data
        """
        return self._make_request('GET', '/auth/me')

    # Project methods
    def get_projects(self) -> ApiResponse:
        """
        Get all projects for the authenticated user.
        
        Returns:
            ApiResponse with list of projects
        """
        return self._make_request('GET', '/projects')

    def create_project(
        self, 
        name: str, 
        color: str, 
        description: Optional[str] = None
    ) -> ApiResponse:
        """
        Create a new project.
        
        Args:
            name: Project name
            color: Project color
            description: Optional project description
            
        Returns:
            ApiResponse with created project data
        """
        data = {
            'name': name,
            'color': color
        }
        if description is not None:
            data['description'] = description
        return self._make_request('POST', '/projects', data)

    def get_project(self, project_id: int) -> ApiResponse:
        """
        Get a specific project by ID.
        
        Args:
            project_id: Project ID
            
        Returns:
            ApiResponse with project data
        """
        return self._make_request('GET', f'/projects/{project_id}')

    def update_project(
        self, 
        project_id: int, 
        name: Optional[str] = None, 
        color: Optional[str] = None, 
        description: Optional[str] = None
    ) -> ApiResponse:
        """
        Update a project.
        
        Args:
            project_id: Project ID to update
            name: New project name
            color: New project color
            description: New project description
            
        Returns:
            ApiResponse with updated project data
        """
        data = {}
        if name is not None:
            data['name'] = name
        if color is not None:
            data['color'] = color
        if description is not None:
            data['description'] = description
        return self._make_request('PUT', f'/projects/{project_id}', data)

    # Todo methods
    def get_todos(
        self, 
        project_id: Optional[int] = None, 
        status: Optional[str] = None, 
        time_horizon: Optional[str] = None
    ) -> ApiResponse:
        """
        Get todos with optional filtering.
        
        Args:
            project_id: Filter by project ID
            status: Filter by status
            time_horizon: Filter by time horizon
            
        Returns:
            ApiResponse with list of todos
        """
        params = {}
        if project_id is not None:
            params['project_id'] = project_id
        if status is not None:
            params['status'] = status
        if time_horizon is not None:
            params['time_horizon'] = time_horizon
        return self._make_request('GET', '/todos', params=params)

    def create_todo(
        self, 
        title: str, 
        project_id: Optional[int] = None, 
        description: Optional[str] = None,
        priority: str = 'medium', 
        estimated_hours: float = 1.0, 
        due_date: Optional[str] = None,
        tags: Optional[List[str]] = None, 
        context: str = 'work', 
        time_horizon: Optional[str] = None
    ) -> ApiResponse:
        """
        Create a new todo item.
        
        Args:
            title: Todo title
            project_id: Optional project ID
            description: Optional description
            priority: Priority level (low, medium, high)
            estimated_hours: Estimated hours to complete
            due_date: Due date in ISO format
            tags: List of tags
            context: Context (work, personal, etc.)
            time_horizon: Time horizon
            
        Returns:
            ApiResponse with created todo data
        """
        data = {
            'title': title,
            'priority': priority,
            'estimated_hours': estimated_hours,
            'context': context
        }
        if project_id is not None:
            data['project_id'] = project_id
        if description is not None:
            data['description'] = description
        if due_date is not None:
            data['due_date'] = due_date
        if tags is not None:
            data['tags'] = tags
        if time_horizon is not None:
            data['time_horizon'] = time_horizon
        return self._make_request('POST', '/todos', data)

    def get_todo(self, todo_id: int) -> ApiResponse:
        """
        Get a specific todo by ID.
        
        Args:
            todo_id: Todo ID
            
        Returns:
            ApiResponse with todo data
        """
        return self._make_request('GET', f'/todos/{todo_id}')

    def update_todo(
        self, 
        todo_id: int, 
        title: Optional[str] = None, 
        project_id: Optional[int] = None,
        description: Optional[str] = None, 
        priority: Optional[str] = None,
        estimated_hours: Optional[float] = None, 
        status: Optional[str] = None,
        due_date: Optional[str] = None, 
        tags: Optional[List[str]] = None,
        context: Optional[str] = None, 
        time_horizon: Optional[str] = None
    ) -> ApiResponse:
        """
        Update a todo item.
        
        Args:
            todo_id: Todo ID to update
            title: New title
            project_id: New project ID
            description: New description
            priority: New priority
            estimated_hours: New estimated hours
            status: New status
            due_date: New due date
            tags: New tags list
            context: New context
            time_horizon: New time horizon
            
        Returns:
            ApiResponse with updated todo data
        """
        data = {}
        if title is not None:
            data['title'] = title
        if project_id is not None:
            data['project_id'] = project_id
        if description is not None:
            data['description'] = description
        if priority is not None:
            data['priority'] = priority
        if estimated_hours is not None:
            data['estimated_hours'] = estimated_hours
        if status is not None:
            data['status'] = status
        if due_date is not None:
            data['due_date'] = due_date
        if tags is not None:
            data['tags'] = tags
        if context is not None:
            data['context'] = context
        if time_horizon is not None:
            data['time_horizon'] = time_horizon
        return self._make_request('PUT', f'/todos/{todo_id}', data)

    def update_todo_bulk(self, todo_id: int, **kwargs: Any) -> ApiResponse:
        """
        Bulk update a todo item with arbitrary fields.
        
        Args:
            todo_id: Todo ID to update
            **kwargs: Fields to update
            
        Returns:
            ApiResponse with updated todo data
        """
        data = {'id': todo_id}
        data.update(kwargs)
        return self._make_request('PUT', '/todos', data)

    def complete_todo(self, todo_id: int, actual_hours: float) -> ApiResponse:
        """
        Mark a todo as completed.
        
        Args:
            todo_id: Todo ID to complete
            actual_hours: Actual hours spent on the todo
            
        Returns:
            ApiResponse with completion result
        """
        return self._make_request('POST', f'/todos/{todo_id}/complete', {
            'actual_hours': actual_hours
        })

    # Reporting methods
    def get_reports(
        self, 
        start_date: str, 
        end_date: str, 
        status: str = 'pending', 
        time_horizon: Optional[str] = None
    ) -> ApiResponse:
        """
        Get reports for a date range.
        
        Args:
            start_date: Start date in ISO format
            end_date: End date in ISO format
            status: Status filter
            time_horizon: Time horizon filter
            
        Returns:
            ApiResponse with report data
        """
        params = {
            'start_date': start_date,
            'end_date': end_date,
            'status': status
        }
        if time_horizon is not None:
            params['time_horizon'] = time_horizon
        return self._make_request('GET', '/reports', params=params)

    # OAuth methods
    def get_oauth_clients(self) -> ApiResponse:
        """
        Get OAuth clients for the authenticated user.
        
        Returns:
            ApiResponse with list of OAuth clients
        """
        return self._make_request('GET', '/oauth/clients')

    def create_oauth_client(
        self, 
        name: str, 
        redirect_uris: List[str], 
        grant_types: Optional[List[str]] = None, 
        scopes: Optional[List[str]] = None
    ) -> ApiResponse:
        """
        Create a new OAuth client.
        
        Args:
            name: Client name
            redirect_uris: List of redirect URIs
            grant_types: List of grant types
            scopes: List of scopes
            
        Returns:
            ApiResponse with created OAuth client data
        """
        data = {
            'name': name,
            'redirectUris': redirect_uris
        }
        if grant_types is not None:
            data['grantTypes'] = grant_types
        if scopes is not None:
            data['scopes'] = scopes
        return self._make_request('POST', '/oauth/clients', data)

    def oauth_token_exchange(
        self, 
        grant_type: str, 
        client_id: str, 
        client_secret: str, 
        **kwargs: Any
    ) -> ApiResponse:
        """
        Exchange OAuth tokens.
        
        Args:
            grant_type: OAuth grant type
            client_id: OAuth client ID
            client_secret: OAuth client secret
            **kwargs: Additional OAuth parameters
            
        Returns:
            ApiResponse with token data
        """
        data = {
            'grant_type': grant_type,
            'client_id': client_id,
            'client_secret': client_secret
        }
        data.update(kwargs)
        
        # OAuth token endpoint uses form encoding
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = self.session.post(
                f"{self.base_url}/oauth/token", 
                data=data, 
                headers=headers
            )
            
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get(
                        'error_description', 
                        error_data.get('error', f'HTTP {response.status_code}')
                    )
                except:
                    error_message = f'HTTP {response.status_code}: {response.text}'
                
                if response.status_code == 401:
                    raise AuthenticationError(error_message)
                elif response.status_code >= 500:
                    raise ServerError(error_message)
                
                return ApiResponse(
                    success=False, 
                    error=error_message, 
                    status_code=response.status_code
                )
            
            try:
                json_data = response.json()
            except:
                json_data = None
            
            return ApiResponse(
                success=True, 
                data=json_data, 
                status_code=response.status_code
            )
            
        except requests.exceptions.RequestException as e:
            raise NetworkError(str(e))


def create_authenticated_client(
    username: str, 
    password: str, 
    base_url: str = "http://localhost:4321/api"
) -> TaskManagerClient:
    """
    Create and authenticate a TaskManager client.
    
    Args:
        username: Username for authentication
        password: Password for authentication
        base_url: Base URL for the TaskManager API
        
    Returns:
        Authenticated TaskManagerClient instance
        
    Raises:
        AuthenticationError: If authentication fails
    """
    client = TaskManagerClient(base_url)
    response = client.login(username, password)
    
    if not response.success:
        raise AuthenticationError(f"Authentication failed: {response.error}")
    
    return client