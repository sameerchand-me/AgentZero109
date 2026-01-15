"""
Recon Agent - Intelligent reconnaissance and target profiling
Identifies tech stack, endpoints, authentication flows, and cloud infrastructure
"""

import asyncio
import aiohttp
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import re
import json


@dataclass
class TechStack:
    """Identified technology stack"""
    frameworks: Set[str] = field(default_factory=set)
    languages: Set[str] = field(default_factory=set)
    servers: Set[str] = field(default_factory=set)
    cdn_waf: Set[str] = field(default_factory=set)
    cloud_provider: Optional[str] = None
    cms: Optional[str] = None
    api_type: Optional[str] = None  # REST, GraphQL, gRPC


@dataclass
class Endpoint:
    """Discovered endpoint"""
    url: str
    method: str
    requires_auth: bool = False
    parameters: List[str] = field(default_factory=list)
    response_type: Optional[str] = None
    interesting: bool = False


@dataclass
class AuthFlow:
    """Authentication flow information"""
    auth_type: str  # JWT, OAuth, Session, API Key
    login_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    refresh_endpoint: Optional[str] = None
    logout_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    password_reset_endpoint: Optional[str] = None


@dataclass
class UserRole:
    """Identified user role"""
    name: str
    permissions: List[str] = field(default_factory=list)
    accessible_endpoints: Set[str] = field(default_factory=set)


class ReconAgent:
    """
    Performs intelligent reconnaissance on targets
    Focuses on high-value information for bug hunting
    """
    
    def __init__(self, target: str, rate_limit: int = 10):
        """
        Initialize Recon Agent
        
        Args:
            target: Base URL of target
            rate_limit: Maximum requests per second
        """
        self.target = target
        self.rate_limit = rate_limit
        self.tech_stack = TechStack()
        self.endpoints: List[Endpoint] = []
        self.auth_flows: List[AuthFlow] = []
        self.roles: List[UserRole] = []
        self.api_graph: Dict[str, List[str]] = {}  # endpoint -> related endpoints
        
        # Request tracking for rate limiting
        self._request_semaphore = asyncio.Semaphore(rate_limit)
        self._last_request_time = 0
    
    async def _rate_limited_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """Make rate-limited HTTP request"""
        async with self._request_semaphore:
            # Simple rate limiting
            await asyncio.sleep(1.0 / self.rate_limit)
            try:
                async with session.request(method, url, timeout=10, **kwargs) as response:
                    return response
            except Exception as e:
                return None
    
    async def identify_tech_stack(self) -> TechStack:
        """
        Identify technology stack of target
        
        Returns:
            TechStack object with identified technologies
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target, timeout=10) as response:
                    headers = response.headers
                    body = await response.text()
                    
                    # Analyze headers
                    self._analyze_headers(headers)
                    
                    # Analyze HTML/response body
                    self._analyze_response_body(body)
                    
                    # Detect cloud provider
                    self._detect_cloud_provider(headers, body)
                    
                    # Check for common API patterns
                    await self._detect_api_type(session)
                    
            except Exception as e:
                print(f"Error in tech stack identification: {e}")
        
        return self.tech_stack
    
    def _analyze_headers(self, headers: Dict[str, str]) -> None:
        """Extract technology information from headers"""
        # Server header
        if 'Server' in headers:
            server = headers['Server'].lower()
            if 'nginx' in server:
                self.tech_stack.servers.add('nginx')
            elif 'apache' in server:
                self.tech_stack.servers.add('apache')
            elif 'cloudflare' in server:
                self.tech_stack.cdn_waf.add('cloudflare')
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By'].lower()
            if 'express' in powered_by:
                self.tech_stack.frameworks.add('Express.js')
                self.tech_stack.languages.add('Node.js')
            elif 'php' in powered_by:
                self.tech_stack.languages.add('PHP')
            elif 'asp.net' in powered_by:
                self.tech_stack.frameworks.add('ASP.NET')
        
        # CDN/WAF detection
        cdn_headers = ['CF-Ray', 'X-Akamai-Transformed', 'X-CDN', 'X-Cache']
        for cdn_header in cdn_headers:
            if cdn_header in headers:
                if 'CF-Ray' in cdn_header:
                    self.tech_stack.cdn_waf.add('Cloudflare')
                elif 'Akamai' in cdn_header:
                    self.tech_stack.cdn_waf.add('Akamai')
    
    def _analyze_response_body(self, body: str) -> None:
        """Analyze response body for technology signatures"""
        body_lower = body.lower()
        
        # Framework detection
        framework_signatures = {
            'react': ['react', 'reactdom'],
            'vue': ['vue.js', 'vuejs'],
            'angular': ['angular', 'ng-'],
            'django': ['csrfmiddlewaretoken', 'django'],
            'rails': ['rails', 'csrf-token'],
            'laravel': ['laravel', 'csrf-token'],
            'wordpress': ['wp-content', 'wp-includes'],
        }
        
        for framework, signatures in framework_signatures.items():
            if any(sig in body_lower for sig in signatures):
                self.tech_stack.frameworks.add(framework)
    
    def _detect_cloud_provider(self, headers: Dict[str, str], body: str) -> None:
        """Detect cloud provider from various signals"""
        # Check headers
        if 'X-Amz-Cf-Id' in headers or 'X-Amz-Request-Id' in headers:
            self.tech_stack.cloud_provider = 'AWS'
        elif 'X-Azure-Ref' in headers:
            self.tech_stack.cloud_provider = 'Azure'
        elif 'X-Goog-' in str(headers):
            self.tech_stack.cloud_provider = 'GCP'
        
        # Check domain patterns
        parsed = urlparse(self.target)
        domain = parsed.netloc
        
        if 'amazonaws.com' in domain or 'cloudfront.net' in domain:
            self.tech_stack.cloud_provider = 'AWS'
        elif 'azurewebsites.net' in domain or 'azure.com' in domain:
            self.tech_stack.cloud_provider = 'Azure'
        elif 'googleapis.com' in domain or 'appspot.com' in domain:
            self.tech_stack.cloud_provider = 'GCP'
    
    async def _detect_api_type(self, session: aiohttp.ClientSession) -> None:
        """Detect API type (REST, GraphQL, gRPC)"""
        # Check for GraphQL
        graphql_endpoints = ['/graphql', '/api/graphql', '/query']
        for endpoint in graphql_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                async with session.post(
                    url,
                    json={'query': '{__schema{types{name}}}'},
                    timeout=5
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if '__schema' in str(data):
                            self.tech_stack.api_type = 'GraphQL'
                            return
            except:
                pass
        
        # Default to REST if we see /api/ patterns
        if '/api/' in self.target:
            self.tech_stack.api_type = 'REST'
    
    async def discover_endpoints(self, wordlist: Optional[List[str]] = None) -> List[Endpoint]:
        """
        Discover API endpoints and interesting paths
        
        Args:
            wordlist: Optional list of paths to check
        
        Returns:
            List of discovered endpoints
        """
        # Common high-value endpoints
        default_paths = [
            '/api/users', '/api/user', '/api/profile',
            '/api/admin', '/api/settings', '/api/config',
            '/api/orders', '/api/payments', '/api/transactions',
            '/api/auth/login', '/api/auth/register', '/api/auth/reset',
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/graphql', '/swagger', '/api-docs',
            '/.git/config', '/.env', '/config',
            '/admin', '/dashboard', '/panel',
        ]
        
        paths_to_check = wordlist if wordlist else default_paths
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in paths_to_check:
                url = urljoin(self.target, path)
                tasks.append(self._check_endpoint(session, url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None and exceptions
            self.endpoints = [ep for ep in results if isinstance(ep, Endpoint)]
        
        return self.endpoints
    
    async def _check_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> Optional[Endpoint]:
        """Check if an endpoint exists and gather info"""
        try:
            async with session.get(url, timeout=5, allow_redirects=False) as response:
                # Consider various status codes as "interesting"
                if response.status in [200, 201, 301, 302, 401, 403]:
                    endpoint = Endpoint(
                        url=url,
                        method='GET',
                        requires_auth=(response.status in [401, 403]),
                        response_type=response.headers.get('Content-Type', '').split(';')[0]
                    )
                    
                    # Mark as interesting based on various criteria
                    endpoint.interesting = self._is_interesting_endpoint(url, response.status)
                    
                    return endpoint
        except:
            pass
        
        return None
    
    def _is_interesting_endpoint(self, url: str, status_code: int) -> bool:
        """Determine if an endpoint is interesting for bug hunting"""
        interesting_patterns = [
            'admin', 'user', 'profile', 'account', 'payment',
            'order', 'transaction', 'config', 'setting', 'auth',
            'password', 'reset', 'token', 'api', 'graphql'
        ]
        
        url_lower = url.lower()
        
        # Check patterns
        if any(pattern in url_lower for pattern in interesting_patterns):
            return True
        
        # 403 endpoints are interesting (potential authz issues)
        if status_code == 403:
            return True
        
        return False
    
    async def map_authentication_flows(self) -> List[AuthFlow]:
        """
        Map authentication and authorization flows
        
        Returns:
            List of identified auth flows
        """
        auth_endpoints = {
            'login': ['/api/auth/login', '/api/login', '/login', '/signin'],
            'register': ['/api/auth/register', '/api/register', '/register', '/signup'],
            'reset': ['/api/auth/reset', '/api/password/reset', '/forgot-password'],
            'token': ['/api/auth/token', '/api/token', '/oauth/token'],
            'refresh': ['/api/auth/refresh', '/api/token/refresh'],
            'logout': ['/api/auth/logout', '/api/logout', '/logout']
        }
        
        found_endpoints = {}
        
        async with aiohttp.ClientSession() as session:
            for endpoint_type, paths in auth_endpoints.items():
                for path in paths:
                    url = urljoin(self.target, path)
                    try:
                        async with session.options(url, timeout=5) as response:
                            if response.status < 500:  # Endpoint exists
                                found_endpoints[endpoint_type] = url
                                break
                    except:
                        continue
        
        # Detect auth type
        auth_type = self._detect_auth_type(found_endpoints)
        
        if found_endpoints:
            auth_flow = AuthFlow(
                auth_type=auth_type,
                login_endpoint=found_endpoints.get('login'),
                token_endpoint=found_endpoints.get('token'),
                refresh_endpoint=found_endpoints.get('refresh'),
                logout_endpoint=found_endpoints.get('logout'),
                registration_endpoint=found_endpoints.get('register'),
                password_reset_endpoint=found_endpoints.get('reset')
            )
            self.auth_flows.append(auth_flow)
        
        return self.auth_flows
    
    def _detect_auth_type(self, endpoints: Dict[str, str]) -> str:
        """Detect authentication mechanism type"""
        if 'token' in endpoints or 'refresh' in endpoints:
            return 'JWT'
        elif 'oauth' in str(endpoints).lower():
            return 'OAuth'
        elif 'login' in endpoints:
            return 'Session'
        else:
            return 'Unknown'
    
    async def enumerate_roles(self) -> List[UserRole]:
        """
        Attempt to enumerate user roles/permission levels
        
        Returns:
            List of identified roles
        """
        # Common role patterns to look for
        common_roles = [
            {'name': 'admin', 'test_paths': ['/admin', '/api/admin']},
            {'name': 'user', 'test_paths': ['/user', '/api/user']},
            {'name': 'guest', 'test_paths': ['/guest', '/api/guest']},
            {'name': 'moderator', 'test_paths': ['/mod', '/api/moderator']},
        ]
        
        async with aiohttp.ClientSession() as session:
            for role_info in common_roles:
                for path in role_info['test_paths']:
                    url = urljoin(self.target, path)
                    try:
                        async with session.get(url, timeout=5) as response:
                            # If we get 401/403, the role likely exists
                            if response.status in [401, 403]:
                                role = UserRole(
                                    name=role_info['name'],
                                    accessible_endpoints={url}
                                )
                                self.roles.append(role)
                                break
                    except:
                        continue
        
        # Add default roles if none found
        if not self.roles:
            self.roles = [
                UserRole(name='admin', permissions=['all']),
                UserRole(name='user', permissions=['read', 'write_own']),
                UserRole(name='guest', permissions=['read_public'])
            ]
        
        return self.roles
    
    def build_endpoint_graph(self) -> Dict[str, List[str]]:
        """
        Build a graph of endpoint relationships
        Useful for understanding API structure and finding hidden endpoints
        
        Returns:
            Dictionary mapping endpoints to related endpoints
        """
        # Group endpoints by prefix
        prefix_groups = {}
        
        for endpoint in self.endpoints:
            parsed = urlparse(endpoint.url)
            path_parts = parsed.path.split('/')
            
            # Use first 2-3 path components as prefix
            if len(path_parts) >= 3:
                prefix = '/'.join(path_parts[:3])
            else:
                prefix = '/'.join(path_parts)
            
            if prefix not in prefix_groups:
                prefix_groups[prefix] = []
            prefix_groups[prefix].append(endpoint.url)
        
        # Build relationships
        for prefix, urls in prefix_groups.items():
            for url in urls:
                self.api_graph[url] = [u for u in urls if u != url]
        
        return self.api_graph
    
    def get_recon_summary(self) -> Dict[str, Any]:
        """Get summary of reconnaissance findings"""
        return {
            'target': self.target,
            'tech_stack': {
                'frameworks': list(self.tech_stack.frameworks),
                'languages': list(self.tech_stack.languages),
                'servers': list(self.tech_stack.servers),
                'cdn_waf': list(self.tech_stack.cdn_waf),
                'cloud_provider': self.tech_stack.cloud_provider,
                'api_type': self.tech_stack.api_type
            },
            'endpoints_found': len(self.endpoints),
            'interesting_endpoints': len([e for e in self.endpoints if e.interesting]),
            'auth_flows': len(self.auth_flows),
            'roles_identified': len(self.roles),
            'api_graph_size': len(self.api_graph)
        }
