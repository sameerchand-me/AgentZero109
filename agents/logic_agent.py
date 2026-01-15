"""
Logic Reasoning Agent - The MOST IMPORTANT agent in AgentZero109
Analyzes business logic, state transitions, and trust boundaries
Answers: "What happens if steps are skipped, reordered, or repeated?"
"""

import asyncio
import aiohttp
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import hashlib

from ..core.state_tracker import StateTracker, StateType
from ..core.role_diff_engine import RoleDiffEngine


class VulnerabilityType(Enum):
    """Types of business logic vulnerabilities"""
    WORKFLOW_BYPASS = "workflow_bypass"
    STATE_VALIDATION_MISSING = "state_validation_missing"
    DOUBLE_SPEND = "double_spend"
    REPLAY_ATTACK = "replay_attack"
    ORDER_ABUSE = "order_abuse"
    PRICE_MANIPULATION = "price_manipulation"
    QUANTITY_MANIPULATION = "quantity_manipulation"
    COUPON_ABUSE = "coupon_abuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROLE_CONFUSION = "role_confusion"
    IDOR = "idor"


@dataclass
class LogicFinding:
    """A business logic vulnerability finding"""
    vuln_type: VulnerabilityType
    severity: str
    confidence: str
    description: str
    reproduction_steps: List[str]
    expected_behavior: str
    actual_behavior: str
    affected_endpoints: List[str]
    business_impact: str
    evidence: Dict[str, Any]


class LogicReasoningAgent:
    """
    The brain of AgentZero109 - analyzes business logic flaws
    Uses state tracking and role comparison to find high-value bugs
    """
    
    def __init__(self, target: str):
        self.target = target
        self.state_tracker = StateTracker()
        self.role_diff_engine = RoleDiffEngine()
        self.findings: List[LogicFinding] = []
        
        # Track tested scenarios
        self.tested_workflows: Set[str] = set()
        self.tested_role_pairs: Set[Tuple[str, str]] = set()
    
    async def analyze_workflow(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        session: Optional[aiohttp.ClientSession] = None
    ) -> List[LogicFinding]:
        """
        Analyze a workflow for logic vulnerabilities
        Tests: step skipping, reordering, repetition
        
        Args:
            workflow_name: Name of the workflow (e.g., "checkout", "registration")
            steps: List of steps with endpoint, method, required_state
            session: Optional aiohttp session
        
        Returns:
            List of logic findings
        """
        findings = []
        
        # Test 1: Can we skip intermediate steps?
        skip_findings = await self._test_step_skipping(workflow_name, steps, session)
        findings.extend(skip_findings)
        
        # Test 2: Can we reorder steps?
        order_findings = await self._test_step_reordering(workflow_name, steps, session)
        findings.extend(order_findings)
        
        # Test 3: Can we repeat steps (double-spend)?
        repeat_findings = await self._test_step_repetition(workflow_name, steps, session)
        findings.extend(repeat_findings)
        
        # Test 4: Can we manipulate parameters between steps?
        param_findings = await self._test_parameter_manipulation(workflow_name, steps, session)
        findings.extend(param_findings)
        
        self.tested_workflows.add(workflow_name)
        self.findings.extend(findings)
        
        return findings
    
    async def _test_step_skipping(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        session: Optional[aiohttp.ClientSession]
    ) -> List[LogicFinding]:
        """Test if workflow steps can be skipped"""
        findings = []
        
        if len(steps) < 3:
            return findings  # Need at least 3 steps to test skipping
        
        # Try to go directly from step 1 to step N
        first_step = steps[0]
        last_step = steps[-1]
        
        # Record the expected full path
        full_path = [step['name'] for step in steps]
        self.state_tracker.record_workflow(full_path)
        
        # Try shortcut path
        if session:
            shortcut_success = await self._try_step_sequence(
                [first_step, last_step],
                session
            )
            
            if shortcut_success:
                skipped_steps = [step['name'] for step in steps[1:-1]]
                
                findings.append(LogicFinding(
                    vuln_type=VulnerabilityType.WORKFLOW_BYPASS,
                    severity='high',
                    confidence='high',
                    description=f"Workflow '{workflow_name}' allows skipping intermediate steps",
                    reproduction_steps=[
                        f"1. Execute: {first_step['method']} {first_step['endpoint']}",
                        f"2. Skip steps: {', '.join(skipped_steps)}",
                        f"3. Execute: {last_step['method']} {last_step['endpoint']}",
                        "4. Observe that final step succeeds without intermediate validation"
                    ],
                    expected_behavior=f"Should require all {len(steps)} steps in order",
                    actual_behavior="Can skip directly to final step",
                    affected_endpoints=[step['endpoint'] for step in [first_step, last_step]],
                    business_impact=f"Attacker can bypass {', '.join(skipped_steps)} controls",
                    evidence={'skipped_steps': skipped_steps, 'workflow': workflow_name}
                ))
        
        return findings
    
    async def _test_step_reordering(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        session: Optional[aiohttp.ClientSession]
    ) -> List[LogicFinding]:
        """Test if workflow steps can be executed in wrong order"""
        findings = []
        
        if len(steps) < 3 or not session:
            return findings
        
        # Try reverse order
        reversed_steps = list(reversed(steps))
        reverse_success = await self._try_step_sequence(reversed_steps, session)
        
        if reverse_success:
            findings.append(LogicFinding(
                vuln_type=VulnerabilityType.ORDER_ABUSE,
                severity='high',
                confidence='medium',
                description=f"Workflow '{workflow_name}' can be executed in reverse order",
                reproduction_steps=[
                    "1. Execute workflow steps in reverse order",
                    f"2. Expected order: {' -> '.join([s['name'] for s in steps])}",
                    f"3. Actual order used: {' -> '.join([s['name'] for s in reversed_steps])}",
                    "4. Observe workflow completes successfully"
                ],
                expected_behavior="Workflow should enforce step ordering",
                actual_behavior="Steps can be executed in any order",
                affected_endpoints=[step['endpoint'] for step in steps],
                business_impact="Attacker can manipulate workflow state by reordering operations",
                evidence={'workflow': workflow_name, 'order_bypass': True}
            ))
        
        return findings
    
    async def _test_step_repetition(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        session: Optional[aiohttp.ClientSession]
    ) -> List[LogicFinding]:
        """Test if steps can be repeated (double-spend attacks)"""
        findings = []
        
        if not session:
            return findings
        
        # Test repeating each step
        for i, step in enumerate(steps):
            if 'financial' in step.get('tags', []) or 'credit' in step.get('tags', []):
                # Try to repeat this step multiple times
                repeat_count = 3
                repeat_success = await self._try_repeat_step(step, repeat_count, session)
                
                if repeat_success:
                    findings.append(LogicFinding(
                        vuln_type=VulnerabilityType.DOUBLE_SPEND,
                        severity='critical',
                        confidence='high',
                        description=f"Step '{step['name']}' in workflow '{workflow_name}' can be repeated",
                        reproduction_steps=[
                            f"1. Complete workflow up to step: {step['name']}",
                            f"2. Repeat request to: {step['method']} {step['endpoint']}",
                            f"3. Observe step executes {repeat_count} times",
                            "4. Check if benefits/credits are applied multiple times"
                        ],
                        expected_behavior="Step should only execute once per workflow session",
                        actual_behavior=f"Step can be repeated {repeat_count} times",
                        affected_endpoints=[step['endpoint']],
                        business_impact="Attacker can replay actions to gain multiple benefits/credits",
                        evidence={'repeated_step': step['name'], 'repeat_count': repeat_count}
                    ))
        
        return findings
    
    async def _test_parameter_manipulation(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        session: Optional[aiohttp.ClientSession]
    ) -> List[LogicFinding]:
        """Test if parameters can be manipulated between steps"""
        findings = []
        
        if not session:
            return findings
        
        # Look for steps that pass data forward
        for i in range(len(steps) - 1):
            current_step = steps[i]
            next_step = steps[i + 1]
            
            # Check if next step uses data from current step
            if 'output_params' in current_step and 'input_params' in next_step:
                # Try manipulating the parameter
                manipulation_types = [
                    ('price', 0.01, 'PRICE_MANIPULATION'),
                    ('amount', 999999, 'QUANTITY_MANIPULATION'),
                    ('quantity', 100, 'QUANTITY_MANIPULATION'),
                    ('total', 0, 'PRICE_MANIPULATION'),
                    ('discount', 100, 'COUPON_ABUSE'),
                ]
                
                for param_name, evil_value, vuln_type in manipulation_types:
                    if param_name in next_step['input_params']:
                        # Test if we can inject evil value
                        success = await self._try_parameter_injection(
                            current_step, next_step, param_name, evil_value, session
                        )
                        
                        if success:
                            findings.append(LogicFinding(
                                vuln_type=VulnerabilityType[vuln_type],
                                severity='critical',
                                confidence='high',
                                description=f"Parameter '{param_name}' can be manipulated between workflow steps",
                                reproduction_steps=[
                                    f"1. Execute step: {current_step['name']}",
                                    f"2. Intercept parameter: {param_name}",
                                    f"3. Change value to: {evil_value}",
                                    f"4. Continue to step: {next_step['name']}",
                                    "5. Observe manipulated value is accepted"
                                ],
                                expected_behavior=f"Parameter '{param_name}' should be validated/recalculated",
                                actual_behavior="Client-provided value is trusted",
                                affected_endpoints=[current_step['endpoint'], next_step['endpoint']],
                                business_impact=f"Attacker can manipulate {param_name} to abuse business logic",
                                evidence={'param': param_name, 'injected_value': evil_value}
                            ))
        
        return findings
    
    async def analyze_authorization(
        self,
        endpoints: List[Dict[str, Any]],
        roles: List[str],
        session: Optional[aiohttp.ClientSession] = None
    ) -> List[LogicFinding]:
        """
        Analyze authorization logic across roles
        Finds IDOR, privilege escalation, role confusion
        
        Args:
            endpoints: List of endpoints to test
            roles: List of role names to test with
            session: Optional aiohttp session
        
        Returns:
            List of authorization findings
        """
        findings = []
        
        # Register roles in diff engine
        for role in roles:
            self.role_diff_engine.add_role(role)
        
        # Test each endpoint with each role
        if session:
            for endpoint in endpoints:
                await self._test_endpoint_with_roles(endpoint, roles, session)
        
        # Analyze differences
        auth_issues = self.role_diff_engine.find_authorization_issues()
        
        # Convert to LogicFindings
        for issue in auth_issues:
            vuln_type = self._map_diff_to_vuln_type(issue.diff_type)
            
            findings.append(LogicFinding(
                vuln_type=vuln_type,
                severity=issue.severity,
                confidence='high',
                description=issue.potential_vulnerability,
                reproduction_steps=[
                    f"1. Authenticate as role: {issue.role2}",
                    f"2. Access endpoint: {issue.endpoint}",
                    "3. Observe access granted to restricted resource",
                    f"4. Compare with role: {issue.role1} which should have access"
                ],
                expected_behavior=f"Only {issue.role1} should have access",
                actual_behavior=f"Both {issue.role1} and {issue.role2} have access",
                affected_endpoints=[issue.endpoint],
                business_impact="Unauthorized access to privileged functionality/data",
                evidence=issue.details
            ))
        
        self.findings.extend(findings)
        return findings
    
    async def _test_endpoint_with_roles(
        self,
        endpoint: Dict[str, Any],
        roles: List[str],
        session: aiohttp.ClientSession
    ) -> None:
        """Test an endpoint with different roles and record responses"""
        for role in roles:
            # In real implementation, would use role-specific auth tokens
            headers = self._get_auth_headers_for_role(role)
            
            try:
                async with session.request(
                    endpoint.get('method', 'GET'),
                    endpoint['url'],
                    headers=headers,
                    timeout=10
                ) as response:
                    body = await response.text()
                    
                    self.role_diff_engine.record_response(
                        endpoint=endpoint['url'],
                        method=endpoint.get('method', 'GET'),
                        role=role,
                        status_code=response.status,
                        headers=dict(response.headers),
                        body=body
                    )
            except Exception as e:
                pass
    
    def _get_auth_headers_for_role(self, role: str) -> Dict[str, str]:
        """Get authentication headers for a specific role"""
        # Placeholder - in real implementation would use actual tokens
        return {
            'Authorization': f'Bearer {role}_token_placeholder',
            'X-User-Role': role
        }
    
    def _map_diff_to_vuln_type(self, diff_type: str) -> VulnerabilityType:
        """Map role diff type to vulnerability type"""
        mapping = {
            'access': VulnerabilityType.PRIVILEGE_ESCALATION,
            'data': VulnerabilityType.IDOR,
            'functionality': VulnerabilityType.ROLE_CONFUSION
        }
        return mapping.get(diff_type, VulnerabilityType.PRIVILEGE_ESCALATION)
    
    async def _try_step_sequence(
        self,
        steps: List[Dict[str, Any]],
        session: aiohttp.ClientSession
    ) -> bool:
        """Try to execute a sequence of steps"""
        # Placeholder implementation
        # Real version would execute actual HTTP requests
        return True  # Simulate success for demonstration
    
    async def _try_repeat_step(
        self,
        step: Dict[str, Any],
        count: int,
        session: aiohttp.ClientSession
    ) -> bool:
        """Try to repeat a step multiple times"""
        # Placeholder implementation
        return True  # Simulate success for demonstration
    
    async def _try_parameter_injection(
        self,
        current_step: Dict[str, Any],
        next_step: Dict[str, Any],
        param_name: str,
        value: Any,
        session: aiohttp.ClientSession
    ) -> bool:
        """Try to inject a manipulated parameter value"""
        # Placeholder implementation
        return True  # Simulate success for demonstration
    
    def ask_what_if(self, question: str, context: Dict[str, Any]) -> str:
        """
        Answer "what if" questions about application behavior
        Examples:
        - "What if step 2 is skipped?"
        - "What if user changes their role parameter?"
        - "What if the same coupon is used twice?"
        
        Args:
            question: The what-if question
            context: Context information (workflow, endpoints, etc.)
        
        Returns:
            Analysis of the potential vulnerability
        """
        question_lower = question.lower()
        
        # Pattern matching for common scenarios
        if 'skip' in question_lower:
            return self._analyze_skip_scenario(context)
        elif 'repeat' in question_lower or 'twice' in question_lower:
            return self._analyze_repeat_scenario(context)
        elif 'change' in question_lower or 'manipulate' in question_lower:
            return self._analyze_manipulation_scenario(context)
        elif 'reorder' in question_lower:
            return self._analyze_reorder_scenario(context)
        else:
            return "Cannot analyze this scenario. Please rephrase."
    
    def _analyze_skip_scenario(self, context: Dict[str, Any]) -> str:
        """Analyze what happens if a step is skipped"""
        return ("Skipping validation steps may allow:\n"
                "- Bypass of payment verification\n"
                "- Bypass of inventory checks\n"
                "- Bypass of authorization checks\n"
                "Test by directly calling later endpoints without prerequisites.")
    
    def _analyze_repeat_scenario(self, context: Dict[str, Any]) -> str:
        """Analyze what happens if a step is repeated"""
        return ("Repeating steps may enable:\n"
                "- Double-spend attacks (credit applied multiple times)\n"
                "- Inventory manipulation\n"
                "- Duplicate discount application\n"
                "Test by replaying requests and checking if effects stack.")
    
    def _analyze_manipulation_scenario(self, context: Dict[str, Any]) -> str:
        """Analyze what happens if parameters are manipulated"""
        return ("Parameter manipulation may allow:\n"
                "- Price changes (set to $0.01)\n"
                "- Quantity manipulation (purchase 999999 items)\n"
                "- Discount abuse (100% off)\n"
                "Test by intercepting and modifying parameter values between steps.")
    
    def _analyze_reorder_scenario(self, context: Dict[str, Any]) -> str:
        """Analyze what happens if steps are reordered"""
        return ("Reordering steps may enable:\n"
                "- State confusion\n"
                "- Authorization bypass\n"
                "- Workflow corruption\n"
                "Test by executing steps in non-standard order.")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of logic analysis"""
        return {
            'workflows_analyzed': len(self.tested_workflows),
            'role_pairs_tested': len(self.tested_role_pairs),
            'total_findings': len(self.findings),
            'critical_findings': len([f for f in self.findings if f.severity == 'critical']),
            'high_findings': len([f for f in self.findings if f.severity == 'high']),
            'vulnerability_types': {
                vtype.value: len([f for f in self.findings if f.vuln_type == vtype])
                for vtype in VulnerabilityType
            }
        }
