"""
Scoring Engine - Evaluates and prioritizes vulnerabilities
Implements the high-payout focus of AgentZero109
"""

from typing import Dict, Any, List, Tuple
from enum import Enum
from dataclasses import dataclass


class VulnerabilityTier(Enum):
    """Vulnerability priority tiers based on payout history"""
    TIER_1_CRITICAL = "tier_1_critical"  # Auth bypass, IDOR, Business Logic, ATO
    TIER_2_HIGH = "tier_2_high"  # SSRF, Advanced Injection
    TIER_3_MEDIUM = "tier_3_medium"  # Lower impact issues
    TIER_4_LOW = "tier_4_low"  # Informational, low-impact


class Exploitability(Enum):
    """How easy it is to exploit the vulnerability"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(Enum):
    """Confidence level in the finding"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class VulnerabilityScore:
    """Complete scoring for a vulnerability"""
    impact_score: float  # 0-10
    exploitability: Exploitability
    confidence: Confidence
    tier: VulnerabilityTier
    estimated_bounty_min: int
    estimated_bounty_max: int
    duplicate_likelihood: float  # 0-1
    priority_score: float  # Overall priority
    should_report: bool


class ScoringEngine:
    """
    Evaluates vulnerabilities based on AgentZero109's payout-focused criteria
    Prioritizes signal over noise
    """
    
    # Tier 1 vulnerability types (highest payout)
    TIER_1_TYPES = {
        'idor', 'bola', 'privilege_escalation', 'role_confusion',
        'missing_ownership_check', 'broken_authorization', 'jwt_bypass',
        'oauth_bypass', 'business_logic_bypass', 'workflow_bypass',
        'double_spend', 'replay_attack', 'free_purchase', 'coupon_abuse',
        'order_abuse', 'missing_state_validation', 'account_takeover',
        'password_reset_poisoning', 'email_change_bypass', 'oauth_misbinding',
        'token_leakage', 'session_fixation', 'token_confusion'
    }
    
    # Tier 2 vulnerability types
    TIER_2_TYPES = {
        'ssrf', 'ssrf_cloud', 'metadata_access', 'internal_access',
        'blind_ssrf', 'sqli', 'second_order_sqli', 'template_injection',
        'command_injection', 'graphql_injection', 'nosql_injection'
    }
    
    # Vulnerability types to ignore (low payout)
    IGNORED_TYPES = {
        'self_xss', 'clickjacking', 'banner_disclosure', 'verbose_error',
        'missing_security_header', 'rate_limit_info', 'autocomplete_enabled',
        'cookie_without_secure', 'open_redirect_low_impact'
    }
    
    def __init__(self, min_priority_threshold: float = 7.0):
        """
        Initialize scoring engine
        
        Args:
            min_priority_threshold: Minimum priority score to proceed with reporting
        """
        self.min_threshold = min_priority_threshold
    
    def classify_tier(self, vuln_type: str) -> VulnerabilityTier:
        """Classify vulnerability into priority tier"""
        vuln_type_lower = vuln_type.lower().replace(' ', '_')
        
        if vuln_type_lower in self.TIER_1_TYPES:
            return VulnerabilityTier.TIER_1_CRITICAL
        elif vuln_type_lower in self.TIER_2_TYPES:
            return VulnerabilityTier.TIER_2_HIGH
        elif vuln_type_lower in self.IGNORED_TYPES:
            return VulnerabilityTier.TIER_4_LOW
        else:
            return VulnerabilityTier.TIER_3_MEDIUM
    
    def calculate_impact_score(
        self,
        vuln_type: str,
        affected_users: str,
        data_exposure: bool,
        privilege_gain: bool,
        financial_impact: bool
    ) -> float:
        """
        Calculate impact score (0-10)
        
        Args:
            vuln_type: Type of vulnerability
            affected_users: 'all', 'authenticated', 'specific'
            data_exposure: Whether sensitive data is exposed
            privilege_gain: Whether attacker gains elevated privileges
            financial_impact: Whether there's direct financial impact
        """
        tier = self.classify_tier(vuln_type)
        
        # Base score from tier
        base_scores = {
            VulnerabilityTier.TIER_1_CRITICAL: 8.0,
            VulnerabilityTier.TIER_2_HIGH: 6.0,
            VulnerabilityTier.TIER_3_MEDIUM: 4.0,
            VulnerabilityTier.TIER_4_LOW: 2.0
        }
        score = base_scores[tier]
        
        # Adjust based on impact factors
        if affected_users == 'all':
            score += 1.5
        elif affected_users == 'authenticated':
            score += 1.0
        
        if data_exposure:
            score += 1.0
        
        if privilege_gain:
            score += 1.5
        
        if financial_impact:
            score += 2.0
        
        return min(score, 10.0)
    
    def estimate_bounty_range(
        self,
        tier: VulnerabilityTier,
        impact_score: float,
        exploitability: Exploitability
    ) -> Tuple[int, int]:
        """
        Estimate bounty range based on historical data
        
        Returns:
            (min_bounty, max_bounty) in USD
        """
        # Base ranges by tier
        ranges = {
            VulnerabilityTier.TIER_1_CRITICAL: (5000, 50000),
            VulnerabilityTier.TIER_2_HIGH: (1000, 10000),
            VulnerabilityTier.TIER_3_MEDIUM: (250, 2000),
            VulnerabilityTier.TIER_4_LOW: (0, 250)
        }
        
        min_bounty, max_bounty = ranges[tier]
        
        # Adjust for exploitability
        if exploitability == Exploitability.HIGH:
            max_bounty = int(max_bounty * 1.5)
        elif exploitability == Exploitability.LOW:
            max_bounty = int(max_bounty * 0.7)
        
        # Adjust for impact score
        if impact_score >= 9.0:
            max_bounty = int(max_bounty * 1.3)
        elif impact_score <= 4.0:
            max_bounty = int(max_bounty * 0.6)
        
        return (min_bounty, max_bounty)
    
    def calculate_duplicate_likelihood(
        self,
        vuln_type: str,
        endpoint_popularity: str,
        disclosure_age_days: int = 0
    ) -> float:
        """
        Estimate likelihood of duplicate (0-1)
        
        Args:
            vuln_type: Type of vulnerability
            endpoint_popularity: 'common', 'uncommon', 'rare'
            disclosure_age_days: Days since similar vulnerability disclosed publicly
        """
        tier = self.classify_tier(vuln_type)
        
        # Base likelihood by tier (more common types are more likely duplicates)
        base_likelihood = {
            VulnerabilityTier.TIER_1_CRITICAL: 0.4,  # High value = more hunters
            VulnerabilityTier.TIER_2_HIGH: 0.3,
            VulnerabilityTier.TIER_3_MEDIUM: 0.2,
            VulnerabilityTier.TIER_4_LOW: 0.1
        }
        likelihood = base_likelihood[tier]
        
        # Adjust for endpoint popularity
        if endpoint_popularity == 'common':
            likelihood += 0.3
        elif endpoint_popularity == 'rare':
            likelihood -= 0.2
        
        # Recent public disclosure increases duplicate risk
        if disclosure_age_days > 0 and disclosure_age_days < 30:
            likelihood += 0.4
        elif disclosure_age_days >= 30 and disclosure_age_days < 90:
            likelihood += 0.2
        
        return max(0.0, min(likelihood, 1.0))
    
    def calculate_priority_score(
        self,
        impact_score: float,
        exploitability: Exploitability,
        confidence: Confidence,
        duplicate_likelihood: float
    ) -> float:
        """
        Calculate overall priority score (0-10)
        This is the master score that determines reporting
        """
        # Base from impact
        priority = impact_score
        
        # Exploitability multiplier
        exploit_multipliers = {
            Exploitability.HIGH: 1.2,
            Exploitability.MEDIUM: 1.0,
            Exploitability.LOW: 0.8
        }
        priority *= exploit_multipliers[exploitability]
        
        # Confidence multiplier
        confidence_multipliers = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4
        }
        priority *= confidence_multipliers[confidence]
        
        # Penalize for duplicate likelihood
        priority *= (1 - duplicate_likelihood * 0.5)
        
        return min(priority, 10.0)
    
    def score_vulnerability(
        self,
        vuln_type: str,
        affected_users: str = 'authenticated',
        data_exposure: bool = False,
        privilege_gain: bool = False,
        financial_impact: bool = False,
        exploitability: Exploitability = Exploitability.MEDIUM,
        confidence: Confidence = Confidence.MEDIUM,
        endpoint_popularity: str = 'uncommon',
        disclosure_age_days: int = 0
    ) -> VulnerabilityScore:
        """
        Complete scoring of a vulnerability
        
        Returns:
            VulnerabilityScore with all metrics and reporting recommendation
        """
        tier = self.classify_tier(vuln_type)
        
        impact_score = self.calculate_impact_score(
            vuln_type, affected_users, data_exposure,
            privilege_gain, financial_impact
        )
        
        duplicate_likelihood = self.calculate_duplicate_likelihood(
            vuln_type, endpoint_popularity, disclosure_age_days
        )
        
        priority_score = self.calculate_priority_score(
            impact_score, exploitability, confidence, duplicate_likelihood
        )
        
        min_bounty, max_bounty = self.estimate_bounty_range(
            tier, impact_score, exploitability
        )
        
        should_report = (
            priority_score >= self.min_threshold and
            confidence != Confidence.LOW and
            tier != VulnerabilityTier.TIER_4_LOW
        )
        
        return VulnerabilityScore(
            impact_score=impact_score,
            exploitability=exploitability,
            confidence=confidence,
            tier=tier,
            estimated_bounty_min=min_bounty,
            estimated_bounty_max=max_bounty,
            duplicate_likelihood=duplicate_likelihood,
            priority_score=priority_score,
            should_report=should_report
        )
    
    def rank_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], VulnerabilityScore]]:
        """
        Score and rank multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts with scoring parameters
        
        Returns:
            List of (vulnerability, score) tuples, sorted by priority
        """
        scored = []
        for vuln in vulnerabilities:
            score = self.score_vulnerability(**vuln)
            scored.append((vuln, score))
        
        # Sort by priority score (highest first)
        scored.sort(key=lambda x: x[1].priority_score, reverse=True)
        
        return scored
