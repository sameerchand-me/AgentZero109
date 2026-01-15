"""
Chaining Engine - Combines low-severity issues into high-impact chains
Models attack graphs and reasons about exploit escalation paths
Turns multiple small findings into critical vulnerabilities
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json


class ChainType(Enum):
    """Types of vulnerability chains"""
    INFO_TO_ATO = "information_disclosure_to_account_takeover"
    XSS_TO_ATO = "xss_to_account_takeover"
    IDOR_TO_PRIV_ESC = "idor_to_privilege_escalation"
    SSRF_TO_RCE = "ssrf_to_remote_code_execution"
    AUTH_BYPASS_CHAIN = "authentication_bypass_chain"
    MULTI_STEP_LOGIC = "multi_step_business_logic"


@dataclass
class VulnerabilityNode:
    """A vulnerability in the attack graph"""
    id: str
    vuln_type: str
    severity: str
    description: str
    endpoint: str
    requirements: List[str] = field(default_factory=list)
    enables: List[str] = field(default_factory=list)
    impact: str = ""


@dataclass
class ExploitChain:
    """A chain of vulnerabilities that combine for high impact"""
    chain_id: str
    chain_type: ChainType
    steps: List[VulnerabilityNode]
    combined_severity: str
    combined_impact: str
    narrative: str
    reproduction_steps: List[str]
    estimated_bounty_increase: float  # Multiplier over individual findings


class ChainingEngine:
    """
    Identifies and chains vulnerabilities for maximum impact
    Transforms low/medium findings into critical chains
    """
    
    def __init__(self):
        self.vulnerabilities: List[VulnerabilityNode] = []
        self.chains: List[ExploitChain] = []
        self.attack_graph: Dict[str, List[str]] = {}
        
        # Chain patterns - how vulnerabilities can combine
        self.chain_patterns = self._initialize_chain_patterns()
    
    def _initialize_chain_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize known vulnerability chaining patterns"""
        return {
            'info_leak_to_ato': {
                'required': ['information_disclosure', 'password_reset'],
                'result_severity': 'critical',
                'bounty_multiplier': 3.0,
                'description': 'Information disclosure enables account takeover'
            },
            'xss_to_ato': {
                'required': ['xss', 'session_token'],
                'result_severity': 'critical',
                'bounty_multiplier': 2.5,
                'description': 'XSS can steal session tokens leading to ATO'
            },
            'idor_chain': {
                'required': ['idor', 'idor'],  # Multiple IDORs
                'result_severity': 'critical',
                'bounty_multiplier': 2.0,
                'description': 'Multiple IDOR vulnerabilities enable full account takeover'
            },
            'ssrf_to_cloud_creds': {
                'required': ['ssrf', 'cloud_metadata'],
                'result_severity': 'critical',
                'bounty_multiplier': 4.0,
                'description': 'SSRF to cloud metadata access exposes credentials'
            },
            'auth_bypass_chain': {
                'required': ['rate_limit_bypass', 'weak_token', 'enumeration'],
                'result_severity': 'critical',
                'bounty_multiplier': 3.5,
                'description': 'Chained authentication weaknesses enable full bypass'
            },
            'logic_to_financial': {
                'required': ['workflow_bypass', 'payment_manipulation'],
                'result_severity': 'critical',
                'bounty_multiplier': 5.0,
                'description': 'Business logic bypass enables financial manipulation'
            }
        }
    
    def add_vulnerability(
        self,
        vuln_id: str,
        vuln_type: str,
        severity: str,
        description: str,
        endpoint: str,
        requirements: Optional[List[str]] = None,
        enables: Optional[List[str]] = None,
        impact: str = ""
    ) -> None:
        """
        Add a vulnerability to the graph
        
        Args:
            vuln_id: Unique identifier
            vuln_type: Type of vulnerability
            severity: Severity level
            description: Description
            endpoint: Affected endpoint
            requirements: What's needed to exploit this
            enables: What this vulnerability enables
            impact: Impact description
        """
        node = VulnerabilityNode(
            id=vuln_id,
            vuln_type=vuln_type,
            severity=severity,
            description=description,
            endpoint=endpoint,
            requirements=requirements or [],
            enables=enables or [],
            impact=impact
        )
        
        self.vulnerabilities.append(node)
        
        # Build attack graph edges
        if vuln_id not in self.attack_graph:
            self.attack_graph[vuln_id] = []
        
        # Link to vulnerabilities this enables
        for enabled_vuln in node.enables:
            self.attack_graph[vuln_id].append(enabled_vuln)
    
    def find_chains(self) -> List[ExploitChain]:
        """
        Identify all possible vulnerability chains
        
        Returns:
            List of exploit chains
        """
        chains = []
        
        # Find chains using pattern matching
        for pattern_name, pattern in self.chain_patterns.items():
            matched_chains = self._find_pattern_chains(pattern_name, pattern)
            chains.extend(matched_chains)
        
        # Find chains using graph traversal
        graph_chains = self._find_graph_chains()
        chains.extend(graph_chains)
        
        # Rank chains by impact
        chains = self._rank_chains(chains)
        
        self.chains = chains
        return chains
    
    def _find_pattern_chains(
        self,
        pattern_name: str,
        pattern: Dict[str, Any]
    ) -> List[ExploitChain]:
        """Find chains matching a specific pattern"""
        chains = []
        required_types = pattern['required']
        
        # Find all combinations of vulnerabilities matching the pattern
        matching_vulns = {
            req_type: [v for v in self.vulnerabilities if req_type in v.vuln_type.lower()]
            for req_type in required_types
        }
        
        # Check if we have all required types
        if all(len(matching_vulns[req_type]) > 0 for req_type in required_types):
            # Create chain from first match of each type
            # (In real implementation, would try all combinations)
            steps = [matching_vulns[req_type][0] for req_type in required_types]
            
            chain = self._create_chain_from_steps(
                pattern_name,
                steps,
                pattern
            )
            chains.append(chain)
        
        return chains
    
    def _find_graph_chains(self) -> List[ExploitChain]:
        """Find chains by traversing the attack graph"""
        chains = []
        
        # DFS from each vulnerability to find paths
        for start_vuln in self.vulnerabilities:
            paths = self._dfs_paths(start_vuln.id, max_depth=4)
            
            # Convert interesting paths to chains
            for path in paths:
                if len(path) >= 2:  # At least 2 vulnerabilities
                    steps = [v for v in self.vulnerabilities if v.id in path]
                    
                    # Calculate combined impact
                    if self._is_impactful_chain(steps):
                        chain = self._create_chain_from_steps(
                            f"graph_chain_{start_vuln.id}",
                            steps,
                            {
                                'result_severity': self._calculate_chain_severity(steps),
                                'bounty_multiplier': 1.5 * len(steps),
                                'description': self._generate_chain_description(steps)
                            }
                        )
                        chains.append(chain)
        
        return chains
    
    def _dfs_paths(
        self,
        start: str,
        max_depth: int,
        current_path: Optional[List[str]] = None,
        visited: Optional[Set[str]] = None
    ) -> List[List[str]]:
        """DFS to find all paths from start node"""
        if current_path is None:
            current_path = []
        if visited is None:
            visited = set()
        
        current_path = current_path + [start]
        visited.add(start)
        
        if len(current_path) >= max_depth:
            return [current_path]
        
        paths = [current_path]
        
        if start in self.attack_graph:
            for next_node in self.attack_graph[start]:
                if next_node not in visited:
                    new_paths = self._dfs_paths(next_node, max_depth, current_path, visited.copy())
                    paths.extend(new_paths)
        
        return paths
    
    def _is_impactful_chain(self, steps: List[VulnerabilityNode]) -> bool:
        """Determine if a chain has significant combined impact"""
        # Chain is impactful if:
        # 1. It includes at least one high/critical vuln, OR
        # 2. It has 3+ medium vulns, OR
        # 3. It leads to sensitive action
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for step in steps:
            severity_counts[step.severity.lower()] += 1
        
        if severity_counts['critical'] > 0:
            return True
        if severity_counts['high'] > 0 and len(steps) >= 2:
            return True
        if severity_counts['medium'] >= 3:
            return True
        
        # Check for sensitive outcomes
        sensitive_keywords = ['account_takeover', 'privilege_escalation', 'payment', 'admin']
        for step in steps:
            if any(keyword in step.description.lower() for keyword in sensitive_keywords):
                return True
        
        return False
    
    def _calculate_chain_severity(self, steps: List[VulnerabilityNode]) -> str:
        """Calculate combined severity for a chain"""
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        total_score = sum(severity_scores.get(step.severity.lower(), 0) for step in steps)
        avg_score = total_score / len(steps) if steps else 0
        
        # If average is high and we have multiple steps, upgrade to critical
        if avg_score >= 3 and len(steps) >= 2:
            return 'critical'
        elif avg_score >= 2:
            return 'high'
        elif avg_score >= 1.5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_chain_description(self, steps: List[VulnerabilityNode]) -> str:
        """Generate description for a chain"""
        if len(steps) == 0:
            return "Empty chain"
        
        types = [step.vuln_type for step in steps]
        return f"Chain: {' → '.join(types)}"
    
    def _create_chain_from_steps(
        self,
        chain_id: str,
        steps: List[VulnerabilityNode],
        pattern: Dict[str, Any]
    ) -> ExploitChain:
        """Create an ExploitChain from vulnerability steps"""
        # Generate narrative
        narrative = self._generate_exploit_narrative(steps, pattern)
        
        # Generate reproduction steps
        repro_steps = []
        for i, step in enumerate(steps, 1):
            repro_steps.append(f"Step {i}: Exploit {step.vuln_type} at {step.endpoint}")
            repro_steps.append(f"  - {step.description}")
        
        repro_steps.append(f"\nCombined Impact: {pattern.get('description', 'Multiple vulnerabilities chained')}")
        
        # Determine chain type
        chain_type = self._determine_chain_type(steps)
        
        return ExploitChain(
            chain_id=chain_id,
            chain_type=chain_type,
            steps=steps,
            combined_severity=pattern.get('result_severity', 'high'),
            combined_impact=pattern.get('description', ''),
            narrative=narrative,
            reproduction_steps=repro_steps,
            estimated_bounty_increase=pattern.get('bounty_multiplier', 1.5)
        )
    
    def _determine_chain_type(self, steps: List[VulnerabilityNode]) -> ChainType:
        """Determine the type of chain based on steps"""
        types_str = ' '.join([step.vuln_type.lower() for step in steps])
        
        if 'information' in types_str and 'account' in types_str:
            return ChainType.INFO_TO_ATO
        elif 'xss' in types_str and ('session' in types_str or 'token' in types_str):
            return ChainType.XSS_TO_ATO
        elif 'idor' in types_str and 'privilege' in types_str:
            return ChainType.IDOR_TO_PRIV_ESC
        elif 'ssrf' in types_str:
            return ChainType.SSRF_TO_RCE
        elif 'auth' in types_str or 'authentication' in types_str:
            return ChainType.AUTH_BYPASS_CHAIN
        else:
            return ChainType.MULTI_STEP_LOGIC
    
    def _generate_exploit_narrative(
        self,
        steps: List[VulnerabilityNode],
        pattern: Dict[str, Any]
    ) -> str:
        """Generate a compelling narrative for the exploit chain"""
        narrative_parts = [
            "# Exploit Chain Narrative\n",
            f"## Overview",
            f"{pattern.get('description', 'Multiple vulnerabilities combine for critical impact')}\n",
            "## Attack Flow\n"
        ]
        
        for i, step in enumerate(steps, 1):
            narrative_parts.append(f"### {i}. {step.vuln_type.replace('_', ' ').title()}")
            narrative_parts.append(f"**Endpoint:** `{step.endpoint}`")
            narrative_parts.append(f"**Description:** {step.description}")
            narrative_parts.append(f"**Individual Severity:** {step.severity}")
            
            if step.enables:
                narrative_parts.append(f"**Enables:** {', '.join(step.enables)}")
            
            narrative_parts.append("")
        
        narrative_parts.append("## Combined Impact")
        narrative_parts.append(f"When chained together, these vulnerabilities escalate to "
                             f"**{pattern.get('result_severity', 'high')}** severity.")
        narrative_parts.append(f"\nEstimated bounty increase: **{pattern.get('bounty_multiplier', 1.5)}x**")
        
        return '\n'.join(narrative_parts)
    
    def _rank_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """Rank chains by impact and bounty potential"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        chains.sort(
            key=lambda c: (
                severity_order.get(c.combined_severity.lower(), 4),
                -c.estimated_bounty_increase,
                -len(c.steps)
            )
        )
        
        return chains
    
    def chain_to_ato(
        self,
        info_disclosure: VulnerabilityNode,
        weak_reset: VulnerabilityNode
    ) -> ExploitChain:
        """
        Specific chain: Information Disclosure → Account Takeover
        
        Args:
            info_disclosure: Info leak vulnerability
            weak_reset: Weak password reset vulnerability
        
        Returns:
            Exploit chain for ATO
        """
        steps = [info_disclosure, weak_reset]
        
        narrative = f"""
# Account Takeover via Information Disclosure

## Step 1: Information Disclosure
{info_disclosure.description}

The information disclosure at `{info_disclosure.endpoint}` leaks sensitive data including:
- Email addresses
- User IDs
- Account metadata

## Step 2: Abuse Password Reset
{weak_reset.description}

Using the leaked information from Step 1, an attacker can:
1. Enumerate valid accounts
2. Exploit weak password reset at `{weak_reset.endpoint}`
3. Gain unauthorized access to victim accounts

## Combined Impact: CRITICAL
This chain enables full account takeover of arbitrary users.
"""
        
        return ExploitChain(
            chain_id="ato_chain_001",
            chain_type=ChainType.INFO_TO_ATO,
            steps=steps,
            combined_severity='critical',
            combined_impact='Full account takeover of arbitrary users',
            narrative=narrative,
            reproduction_steps=[
                f"1. Access {info_disclosure.endpoint} to leak user information",
                "2. Extract target user email/ID from leaked data",
                f"3. Use leaked info to exploit {weak_reset.endpoint}",
                "4. Reset victim's password without authorization",
                "5. Log in as victim user"
            ],
            estimated_bounty_increase=3.0
        )
    
    def get_chaining_summary(self) -> Dict[str, Any]:
        """Get summary of chaining analysis"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_chains_found': len(self.chains),
            'critical_chains': len([c for c in self.chains if c.combined_severity == 'critical']),
            'high_chains': len([c for c in self.chains if c.combined_severity == 'high']),
            'avg_bounty_multiplier': sum(c.estimated_bounty_increase for c in self.chains) / len(self.chains) if self.chains else 0,
            'chain_types': {
                ct.value: len([c for c in self.chains if c.chain_type == ct])
                for ct in ChainType
            }
        }
