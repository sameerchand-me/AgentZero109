"""
State Tracker - Tracks application state transitions and trust boundaries
Critical for detecting business logic flaws
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class StateType(Enum):
    """Types of application states"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    WORKFLOW = "workflow"
    SESSION = "session"
    TRANSACTION = "transaction"
    RESOURCE_ACCESS = "resource_access"


@dataclass
class StateTransition:
    """Represents a state transition in the application"""
    from_state: str
    to_state: str
    action: str
    timestamp: datetime
    required_conditions: List[str]
    observed_validations: List[str]
    missing_validations: List[str] = field(default_factory=list)
    trust_boundary_crossed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustBoundary:
    """Represents a trust boundary in the application"""
    name: str
    boundary_type: str  # 'authentication', 'authorization', 'role', 'data_access'
    required_checks: List[str]
    observed_checks: List[str]
    endpoints: Set[str] = field(default_factory=set)


class StateTracker:
    """
    Tracks application state transitions and identifies missing validations
    Essential for business logic vulnerability detection
    """
    
    def __init__(self):
        self.states: Dict[str, Dict[str, Any]] = {}
        self.transitions: List[StateTransition] = []
        self.trust_boundaries: Dict[str, TrustBoundary] = {}
        self.state_graph: Dict[str, Set[str]] = {}  # State -> reachable states
        self.workflow_paths: List[List[str]] = []
    
    def register_state(
        self,
        state_name: str,
        state_type: StateType,
        required_preconditions: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a known application state
        
        Args:
            state_name: Unique identifier for the state
            state_type: Type of state
            required_preconditions: Conditions that should be met to reach this state
            metadata: Additional state information
        """
        self.states[state_name] = {
            'type': state_type,
            'preconditions': required_preconditions,
            'metadata': metadata or {},
            'observed_count': 0
        }
        
        if state_name not in self.state_graph:
            self.state_graph[state_name] = set()
    
    def record_transition(
        self,
        from_state: str,
        to_state: str,
        action: str,
        observed_validations: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> StateTransition:
        """
        Record a state transition observation
        
        Args:
            from_state: Starting state
            to_state: Ending state
            action: Action that triggered transition
            observed_validations: Validations that were performed
            metadata: Additional transition data
        
        Returns:
            StateTransition object with analysis
        """
        # Get expected conditions for target state
        expected_conditions = []
        if to_state in self.states:
            expected_conditions = self.states[to_state]['preconditions']
            self.states[to_state]['observed_count'] += 1
        
        # Identify missing validations
        missing = [cond for cond in expected_conditions 
                  if cond not in observed_validations]
        
        # Check if trust boundary was crossed
        trust_boundary_crossed = self._is_trust_boundary_crossed(from_state, to_state)
        
        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            action=action,
            timestamp=datetime.now(),
            required_conditions=expected_conditions,
            observed_validations=observed_validations,
            missing_validations=missing,
            trust_boundary_crossed=trust_boundary_crossed,
            metadata=metadata or {}
        )
        
        self.transitions.append(transition)
        self.state_graph[from_state].add(to_state)
        
        return transition
    
    def register_trust_boundary(
        self,
        name: str,
        boundary_type: str,
        required_checks: List[str],
        endpoints: Optional[Set[str]] = None
    ) -> None:
        """
        Register a trust boundary in the application
        
        Args:
            name: Boundary identifier
            boundary_type: Type of boundary
            required_checks: Security checks that should be performed
            endpoints: Endpoints protected by this boundary
        """
        self.trust_boundaries[name] = TrustBoundary(
            name=name,
            boundary_type=boundary_type,
            required_checks=required_checks,
            observed_checks=[],
            endpoints=endpoints or set()
        )
    
    def validate_boundary_crossing(
        self,
        boundary_name: str,
        observed_checks: List[str],
        endpoint: str
    ) -> List[str]:
        """
        Validate that proper checks were performed when crossing a trust boundary
        
        Args:
            boundary_name: Name of boundary being crossed
            observed_checks: Checks that were actually performed
            endpoint: Endpoint where crossing occurred
        
        Returns:
            List of missing checks (empty if all checks performed)
        """
        if boundary_name not in self.trust_boundaries:
            return []
        
        boundary = self.trust_boundaries[boundary_name]
        boundary.observed_checks.extend(observed_checks)
        boundary.endpoints.add(endpoint)
        
        missing = [check for check in boundary.required_checks 
                  if check not in observed_checks]
        
        return missing
    
    def _is_trust_boundary_crossed(self, from_state: str, to_state: str) -> bool:
        """Determine if transition crosses a trust boundary"""
        # Check if states have different privilege levels or authentication requirements
        if from_state not in self.states or to_state not in self.states:
            return False
        
        from_type = self.states[from_state]['type']
        to_type = self.states[to_state]['type']
        
        # Transitions to authentication/authorization states cross boundaries
        return to_type in [StateType.AUTHENTICATION, StateType.AUTHORIZATION]
    
    def find_bypasses(self) -> List[Dict[str, Any]]:
        """
        Analyze recorded transitions to find potential bypasses
        
        Returns:
            List of potential bypass vulnerabilities
        """
        bypasses = []
        
        # Check for transitions with missing validations
        for transition in self.transitions:
            if transition.missing_validations:
                bypasses.append({
                    'type': 'missing_validation',
                    'severity': 'high' if transition.trust_boundary_crossed else 'medium',
                    'from_state': transition.from_state,
                    'to_state': transition.to_state,
                    'action': transition.action,
                    'missing_checks': transition.missing_validations,
                    'description': f"Transition from {transition.from_state} to {transition.to_state} "
                                 f"missing validations: {', '.join(transition.missing_validations)}"
                })
        
        # Check for unexpected state reachability
        bypasses.extend(self._check_unexpected_paths())
        
        return bypasses
    
    def _check_unexpected_paths(self) -> List[Dict[str, Any]]:
        """Check for states that are reachable without proper intermediate steps"""
        issues = []
        
        # Look for direct paths that should require intermediate states
        for from_state, reachable in self.state_graph.items():
            for to_state in reachable:
                if to_state in self.states:
                    preconditions = self.states[to_state]['preconditions']
                    
                    # If target has preconditions that reference other states
                    state_preconditions = [p for p in preconditions if 'state:' in p]
                    if state_preconditions:
                        issues.append({
                            'type': 'state_order_violation',
                            'severity': 'medium',
                            'from_state': from_state,
                            'to_state': to_state,
                            'expected_intermediate_states': state_preconditions,
                            'description': f"Direct transition from {from_state} to {to_state} "
                                         f"may bypass required intermediate steps"
                        })
        
        return issues
    
    def record_workflow(self, steps: List[str]) -> None:
        """Record a complete workflow path"""
        self.workflow_paths.append(steps)
    
    def find_workflow_bypasses(self) -> List[Dict[str, Any]]:
        """
        Analyze workflows to find steps that can be skipped
        
        Returns:
            List of potential workflow bypass vulnerabilities
        """
        if len(self.workflow_paths) < 2:
            return []
        
        bypasses = []
        
        # Compare different paths to same end state
        end_states = {}
        for path in self.workflow_paths:
            if len(path) > 0:
                end = path[-1]
                if end not in end_states:
                    end_states[end] = []
                end_states[end].append(path)
        
        # Find cases where same end state reached via different paths
        for end_state, paths in end_states.items():
            if len(paths) > 1:
                # Find shortest vs longest path
                shortest = min(paths, key=len)
                longest = max(paths, key=len)
                
                if len(shortest) < len(longest):
                    skipped_steps = set(longest) - set(shortest)
                    if skipped_steps:
                        bypasses.append({
                            'type': 'workflow_step_bypass',
                            'severity': 'high',
                            'end_state': end_state,
                            'full_path': longest,
                            'bypass_path': shortest,
                            'skipped_steps': list(skipped_steps),
                            'description': f"Workflow can reach {end_state} bypassing steps: "
                                         f"{', '.join(skipped_steps)}"
                        })
        
        return bypasses
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of tracked state information"""
        return {
            'total_states': len(self.states),
            'total_transitions': len(self.transitions),
            'trust_boundaries': len(self.trust_boundaries),
            'workflow_paths': len(self.workflow_paths),
            'transitions_with_missing_validations': sum(
                1 for t in self.transitions if t.missing_validations
            ),
            'trust_boundary_crossings': sum(
                1 for t in self.transitions if t.trust_boundary_crossed
            )
        }
