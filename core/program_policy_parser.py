"""
Program Policy Parser - Parses and enforces bug bounty program rules
Ensures AgentZero109 operates within program constraints
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
import re
import yaml


@dataclass
class ProgramScope:
    """Defines the scope of a bug bounty program"""
    in_scope_domains: List[str]
    in_scope_urls: List[str]
    out_of_scope: List[str]
    allowed_vulnerability_types: Set[str]
    excluded_vulnerability_types: Set[str]
    max_severity_allowed: str
    safe_harbor: bool


@dataclass
class ProgramRules:
    """Rules and constraints for a bug bounty program"""
    no_dos: bool = True
    no_social_engineering: bool = True
    no_physical_attacks: bool = True
    requires_authentication: bool = True
    rate_limit: Optional[int] = None  # requests per minute
    allowed_testing_hours: Optional[str] = None
    notification_required: bool = False
    custom_rules: List[str] = None


@dataclass
class PayoutInfo:
    """Historical payout information for the program"""
    min_payout: int
    max_payout: int
    avg_payout: int
    accepted_vulnerabilities: Dict[str, int]  # vuln_type -> count
    rejected_patterns: List[str]
    duplicate_rate: float


class ProgramPolicyParser:
    """
    Parses bug bounty program policies and enforces compliance
    Adapts AgentZero109 behavior to program-specific rules
    """
    
    def __init__(self, config_file: Optional[str] = None):
        self.scope: Optional[ProgramScope] = None
        self.rules: Optional[ProgramRules] = None
        self.payout_info: Optional[PayoutInfo] = None
        self.program_name: Optional[str] = None
        
        if config_file:
            self.load_from_file(config_file)
    
    def load_from_file(self, config_file: str) -> None:
        """Load program policy from YAML file"""
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        self.program_name = config.get('program_name')
        
        # Parse scope
        scope_config = config.get('scope', {})
        self.scope = ProgramScope(
            in_scope_domains=scope_config.get('in_scope_domains', []),
            in_scope_urls=scope_config.get('in_scope_urls', []),
            out_of_scope=scope_config.get('out_of_scope', []),
            allowed_vulnerability_types=set(scope_config.get('allowed_types', [])),
            excluded_vulnerability_types=set(scope_config.get('excluded_types', [])),
            max_severity_allowed=scope_config.get('max_severity', 'critical'),
            safe_harbor=scope_config.get('safe_harbor', False)
        )
        
        # Parse rules
        rules_config = config.get('rules', {})
        self.rules = ProgramRules(
            no_dos=rules_config.get('no_dos', True),
            no_social_engineering=rules_config.get('no_social_engineering', True),
            no_physical_attacks=rules_config.get('no_physical_attacks', True),
            requires_authentication=rules_config.get('requires_authentication', True),
            rate_limit=rules_config.get('rate_limit'),
            allowed_testing_hours=rules_config.get('allowed_testing_hours'),
            notification_required=rules_config.get('notification_required', False),
            custom_rules=rules_config.get('custom_rules', [])
        )
        
        # Parse payout info
        payout_config = config.get('payout_info', {})
        self.payout_info = PayoutInfo(
            min_payout=payout_config.get('min_payout', 0),
            max_payout=payout_config.get('max_payout', 0),
            avg_payout=payout_config.get('avg_payout', 0),
            accepted_vulnerabilities=payout_config.get('accepted_vulnerabilities', {}),
            rejected_patterns=payout_config.get('rejected_patterns', []),
            duplicate_rate=payout_config.get('duplicate_rate', 0.3)
        )
    
    def create_from_dict(self, config: Dict[str, Any]) -> None:
        """Create policy from dictionary (useful for API-fetched policies)"""
        # Similar to load_from_file but takes dict input
        self.program_name = config.get('program_name')
        
        scope_config = config.get('scope', {})
        self.scope = ProgramScope(
            in_scope_domains=scope_config.get('in_scope_domains', []),
            in_scope_urls=scope_config.get('in_scope_urls', []),
            out_of_scope=scope_config.get('out_of_scope', []),
            allowed_vulnerability_types=set(scope_config.get('allowed_types', [])),
            excluded_vulnerability_types=set(scope_config.get('excluded_types', [])),
            max_severity_allowed=scope_config.get('max_severity', 'critical'),
            safe_harbor=scope_config.get('safe_harbor', False)
        )
        
        rules_config = config.get('rules', {})
        self.rules = ProgramRules(
            no_dos=rules_config.get('no_dos', True),
            no_social_engineering=rules_config.get('no_social_engineering', True),
            no_physical_attacks=rules_config.get('no_physical_attacks', True),
            requires_authentication=rules_config.get('requires_authentication', True),
            rate_limit=rules_config.get('rate_limit'),
            allowed_testing_hours=rules_config.get('allowed_testing_hours'),
            notification_required=rules_config.get('notification_required', False),
            custom_rules=rules_config.get('custom_rules', [])
        )
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is in scope for testing
        
        Args:
            url: URL to check
        
        Returns:
            True if in scope, False otherwise
        """
        if not self.scope:
            return False
        
        # Check out of scope first
        for pattern in self.scope.out_of_scope:
            if self._matches_pattern(url, pattern):
                return False
        
        # Check in scope domains
        for domain in self.scope.in_scope_domains:
            if domain in url:
                return True
        
        # Check in scope URLs
        for scope_url in self.scope.in_scope_urls:
            if self._matches_pattern(url, scope_url):
                return True
        
        return False
    
    def _matches_pattern(self, url: str, pattern: str) -> bool:
        """Check if URL matches a pattern (supports wildcards)"""
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
        return bool(re.match(regex_pattern, url))
    
    def is_vulnerability_allowed(self, vuln_type: str) -> bool:
        """
        Check if a vulnerability type is allowed by the program
        
        Args:
            vuln_type: Type of vulnerability
        
        Returns:
            True if allowed, False otherwise
        """
        if not self.scope:
            return True
        
        vuln_type_lower = vuln_type.lower()
        
        # Check exclusions first
        if vuln_type_lower in self.scope.excluded_vulnerability_types:
            return False
        
        # If there's an allow list, check it
        if self.scope.allowed_vulnerability_types:
            return vuln_type_lower in self.scope.allowed_vulnerability_types
        
        return True
    
    def get_rate_limit(self) -> Optional[int]:
        """Get the rate limit for this program"""
        return self.rules.rate_limit if self.rules else None
    
    def requires_notification(self) -> bool:
        """Check if program requires notification before testing"""
        return self.rules.notification_required if self.rules else False
    
    def get_historical_acceptance_rate(self, vuln_type: str) -> float:
        """
        Get historical acceptance rate for a vulnerability type
        
        Args:
            vuln_type: Type of vulnerability
        
        Returns:
            Acceptance rate (0-1), or 0.5 if unknown
        """
        if not self.payout_info or not self.payout_info.accepted_vulnerabilities:
            return 0.5
        
        total_accepted = sum(self.payout_info.accepted_vulnerabilities.values())
        if total_accepted == 0:
            return 0.5
        
        vuln_count = self.payout_info.accepted_vulnerabilities.get(vuln_type, 0)
        return vuln_count / total_accepted
    
    def is_likely_duplicate(self, vuln_type: str) -> bool:
        """
        Check if vulnerability type has high duplicate rate for this program
        
        Args:
            vuln_type: Type of vulnerability
        
        Returns:
            True if likely duplicate based on historical data
        """
        if not self.payout_info:
            return False
        
        # Check rejected patterns
        for pattern in self.payout_info.rejected_patterns:
            if pattern.lower() in vuln_type.lower():
                return True
        
        # Check if this type has been over-reported
        if self.payout_info.accepted_vulnerabilities:
            acceptance_rate = self.get_historical_acceptance_rate(vuln_type)
            if acceptance_rate < 0.1:  # Less than 10% acceptance
                return True
        
        return False
    
    def get_expected_payout_range(self, vuln_type: str, severity: str) -> tuple[int, int]:
        """
        Get expected payout range for a vulnerability type
        
        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
        
        Returns:
            (min_payout, max_payout) tuple
        """
        if not self.payout_info:
            return (0, 0)
        
        # Adjust based on severity
        severity_multipliers = {
            'critical': 1.0,
            'high': 0.6,
            'medium': 0.3,
            'low': 0.1
        }
        
        multiplier = severity_multipliers.get(severity.lower(), 0.5)
        
        min_payout = int(self.payout_info.min_payout * multiplier)
        max_payout = int(self.payout_info.max_payout * multiplier)
        
        return (min_payout, max_payout)
    
    def validate_testing_time(self) -> bool:
        """Check if current time is within allowed testing hours"""
        if not self.rules or not self.rules.allowed_testing_hours:
            return True
        
        # Simple implementation - can be enhanced with actual time parsing
        # Format expected: "09:00-17:00 UTC" or "anytime"
        if self.rules.allowed_testing_hours.lower() == "anytime":
            return True
        
        # For now, return True - full implementation would parse time ranges
        return True
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get summary of program compliance settings"""
        return {
            'program_name': self.program_name,
            'safe_harbor': self.scope.safe_harbor if self.scope else False,
            'rate_limit': self.get_rate_limit(),
            'in_scope_domains': len(self.scope.in_scope_domains) if self.scope else 0,
            'excluded_types': len(self.scope.excluded_vulnerability_types) if self.scope else 0,
            'notification_required': self.requires_notification(),
            'avg_payout': self.payout_info.avg_payout if self.payout_info else 0
        }
