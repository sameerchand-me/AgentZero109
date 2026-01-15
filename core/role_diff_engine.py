"""
Role Diff Engine - Compares responses across different user roles
Essential for detecting authorization and access control vulnerabilities
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from difflib import unified_diff
import json
import hashlib


@dataclass
class RoleResponse:
    """Response data for a specific role"""
    role: str
    status_code: int
    headers: Dict[str, str]
    body: str
    body_hash: str
    response_time: float
    endpoint: str
    method: str


@dataclass
class RoleDifference:
    """Represents a difference in responses between roles"""
    endpoint: str
    method: str
    role1: str
    role2: str
    diff_type: str  # 'access', 'data', 'functionality'
    severity: str  # 'critical', 'high', 'medium', 'low'
    details: Dict[str, Any]
    potential_vulnerability: str


class RoleDiffEngine:
    """
    Compares API/endpoint responses across different user roles
    Identifies authorization bypass and broken access control
    """
    
    def __init__(self):
        self.responses: Dict[str, Dict[str, RoleResponse]] = {}  # endpoint -> role -> response
        self.roles: Set[str] = set()
        self.differences: List[RoleDifference] = []
    
    def add_role(self, role_name: str, permissions: Optional[List[str]] = None) -> None:
        """
        Register a user role
        
        Args:
            role_name: Name of the role (e.g., 'admin', 'user', 'guest')
            permissions: Expected permissions for this role
        """
        self.roles.add(role_name)
    
    def record_response(
        self,
        endpoint: str,
        method: str,
        role: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        response_time: float = 0.0
    ) -> None:
        """
        Record a response for a specific role
        
        Args:
            endpoint: API endpoint or URL path
            method: HTTP method
            role: User role making the request
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            response_time: Time taken for response
        """
        key = f"{method}:{endpoint}"
        
        if key not in self.responses:
            self.responses[key] = {}
        
        # Hash body for quick comparison
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        
        self.responses[key][role] = RoleResponse(
            role=role,
            status_code=status_code,
            headers=headers,
            body=body,
            body_hash=body_hash,
            response_time=response_time,
            endpoint=endpoint,
            method=method
        )
        
        self.roles.add(role)
    
    def compare_roles(
        self,
        role1: str,
        role2: str,
        endpoint: Optional[str] = None
    ) -> List[RoleDifference]:
        """
        Compare responses between two roles
        
        Args:
            role1: First role to compare
            role2: Second role to compare
            endpoint: Specific endpoint to compare (None for all)
        
        Returns:
            List of differences found
        """
        differences = []
        
        # Determine which endpoints to compare
        endpoints_to_check = [endpoint] if endpoint else self.responses.keys()
        
        for ep_key in endpoints_to_check:
            if ep_key not in self.responses:
                continue
            
            if role1 not in self.responses[ep_key] or role2 not in self.responses[ep_key]:
                continue
            
            resp1 = self.responses[ep_key][role1]
            resp2 = self.responses[ep_key][role2]
            
            # Compare access (status codes)
            access_diff = self._compare_access(resp1, resp2)
            if access_diff:
                differences.append(access_diff)
            
            # If both have access, compare data
            if resp1.status_code == 200 and resp2.status_code == 200:
                data_diffs = self._compare_data(resp1, resp2)
                differences.extend(data_diffs)
        
        self.differences.extend(differences)
        return differences
    
    def _compare_access(
        self,
        resp1: RoleResponse,
        resp2: RoleResponse
    ) -> Optional[RoleDifference]:
        """Compare access levels between two role responses"""
        # Check for authorization bypass
        if resp1.status_code == 403 and resp2.status_code == 200:
            return RoleDifference(
                endpoint=resp1.endpoint,
                method=resp1.method,
                role1=resp1.role,
                role2=resp2.role,
                diff_type='access',
                severity='critical',
                details={
                    'role1_status': resp1.status_code,
                    'role2_status': resp2.status_code,
                    'role1_denied': True,
                    'role2_allowed': True
                },
                potential_vulnerability='Authorization Bypass - Lower privilege role can access '
                                       f'endpoint that should be restricted'
            )
        
        # Check for unexpected access patterns
        if resp1.status_code == 200 and resp2.status_code == 403:
            # This is expected - higher privilege has access
            return None
        
        # Both have access but one is redirected
        if resp1.status_code in [301, 302] and resp2.status_code == 200:
            return RoleDifference(
                endpoint=resp1.endpoint,
                method=resp1.method,
                role1=resp1.role,
                role2=resp2.role,
                diff_type='access',
                severity='medium',
                details={
                    'role1_status': resp1.status_code,
                    'role2_status': resp2.status_code,
                    'role1_redirect': resp1.headers.get('Location', 'unknown')
                },
                potential_vulnerability='Inconsistent access control - role-based redirect behavior'
            )
        
        return None
    
    def _compare_data(
        self,
        resp1: RoleResponse,
        resp2: RoleResponse
    ) -> List[RoleDifference]:
        """Compare data in responses between two roles"""
        differences = []
        
        # Quick check - if bodies are identical, no data differences
        if resp1.body_hash == resp2.body_hash:
            return differences
        
        # Try to parse as JSON for structured comparison
        try:
            data1 = json.loads(resp1.body)
            data2 = json.loads(resp2.body)
            
            # Compare keys
            keys1 = set(self._flatten_keys(data1))
            keys2 = set(self._flatten_keys(data2))
            
            # Check for data leakage (lower privilege sees more data)
            extra_in_resp2 = keys2 - keys1
            if extra_in_resp2 and self._is_lower_privilege(resp1.role, resp2.role):
                differences.append(RoleDifference(
                    endpoint=resp1.endpoint,
                    method=resp1.method,
                    role1=resp1.role,
                    role2=resp2.role,
                    diff_type='data',
                    severity='high',
                    details={
                        'extra_fields_in_lower_role': list(extra_in_resp2),
                        'field_count_high': len(keys1),
                        'field_count_low': len(keys2)
                    },
                    potential_vulnerability='Data Leakage - Lower privilege role receives '
                                           f'additional fields: {", ".join(list(extra_in_resp2)[:5])}'
                ))
            
            # Check for IDOR-like patterns
            idor_diff = self._check_idor_patterns(data1, data2, resp1, resp2)
            if idor_diff:
                differences.append(idor_diff)
        
        except json.JSONDecodeError:
            # If not JSON, do text diff
            text_diff = self._text_diff_analysis(resp1, resp2)
            if text_diff:
                differences.append(text_diff)
        
        return differences
    
    def _flatten_keys(self, data: Any, prefix: str = '') -> List[str]:
        """Recursively flatten nested dictionary keys"""
        keys = []
        if isinstance(data, dict):
            for k, v in data.items():
                new_prefix = f"{prefix}.{k}" if prefix else k
                keys.append(new_prefix)
                if isinstance(v, (dict, list)):
                    keys.extend(self._flatten_keys(v, new_prefix))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    keys.extend(self._flatten_keys(item, f"{prefix}[{i}]"))
        return keys
    
    def _check_idor_patterns(
        self,
        data1: Any,
        data2: Any,
        resp1: RoleResponse,
        resp2: RoleResponse
    ) -> Optional[RoleDifference]:
        """Check for IDOR-like patterns where roles see each other's data"""
        # Look for ID/user reference mismatches
        if isinstance(data1, dict) and isinstance(data2, dict):
            # Check for user_id, owner_id, etc. fields
            id_fields = ['user_id', 'owner_id', 'creator_id', 'account_id', 'customer_id']
            
            for field in id_fields:
                if field in data1 and field in data2:
                    if data1[field] != data2[field]:
                        # Different users can see different user IDs - potential IDOR
                        return RoleDifference(
                            endpoint=resp1.endpoint,
                            method=resp1.method,
                            role1=resp1.role,
                            role2=resp2.role,
                            diff_type='data',
                            severity='critical',
                            details={
                                'field': field,
                                'value_role1': str(data1[field]),
                                'value_role2': str(data2[field]),
                                'pattern': 'IDOR'
                            },
                            potential_vulnerability=f'Potential IDOR - Different roles see different '
                                                   f'{field} values, may indicate broken object-level authorization'
                        )
        
        return None
    
    def _text_diff_analysis(
        self,
        resp1: RoleResponse,
        resp2: RoleResponse
    ) -> Optional[RoleDifference]:
        """Analyze text differences between responses"""
        # Calculate similarity
        lines1 = resp1.body.split('\n')
        lines2 = resp2.body.split('\n')
        
        diff = list(unified_diff(lines1, lines2, lineterm=''))
        
        if len(diff) > 10:  # Significant differences
            return RoleDifference(
                endpoint=resp1.endpoint,
                method=resp1.method,
                role1=resp1.role,
                role2=resp2.role,
                diff_type='data',
                severity='medium',
                details={
                    'diff_lines': len(diff),
                    'body_length_role1': len(resp1.body),
                    'body_length_role2': len(resp2.body)
                },
                potential_vulnerability='Significant response differences between roles - '
                                       'manual review recommended'
            )
        
        return None
    
    def _is_lower_privilege(self, role1: str, role2: str) -> bool:
        """Determine if role2 is lower privilege than role1"""
        # Simple heuristic - can be made more sophisticated
        privilege_order = ['admin', 'moderator', 'user', 'guest', 'anonymous']
        
        try:
            idx1 = privilege_order.index(role1.lower())
            idx2 = privilege_order.index(role2.lower())
            return idx2 > idx1
        except ValueError:
            # Unknown roles, assume equal
            return False
    
    def find_authorization_issues(self) -> List[RoleDifference]:
        """
        Analyze all recorded responses to find authorization issues
        
        Returns:
            List of potential authorization vulnerabilities
        """
        auth_issues = []
        
        # Compare all role pairs
        roles_list = list(self.roles)
        for i, role1 in enumerate(roles_list):
            for role2 in roles_list[i+1:]:
                diffs = self.compare_roles(role1, role2)
                auth_issues.extend([d for d in diffs if d.severity in ['critical', 'high']])
        
        return auth_issues
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of role comparison analysis"""
        return {
            'total_roles': len(self.roles),
            'total_endpoints_tested': len(self.responses),
            'total_differences_found': len(self.differences),
            'critical_differences': len([d for d in self.differences if d.severity == 'critical']),
            'high_differences': len([d for d in self.differences if d.severity == 'high']),
            'roles': list(self.roles)
        }
