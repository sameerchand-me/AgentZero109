#!/usr/bin/env python3
"""
Quick test script to validate AgentZero109 installation
"""

import sys
import importlib

def test_imports():
    """Test that all core modules can be imported"""
    modules = [
        ('agents.recon_agent', 'ReconAgent'),
        ('agents.logic_agent', 'LogicReasoningAgent'),
        ('agents.exploit_agent', 'ExploitValidationAgent'),
        ('agents.chain_agent', 'ChainingEngine'),
        ('agents.report_agent', 'ReportAgent'),
        ('core.state_tracker', 'StateTracker'),
        ('core.role_diff_engine', 'RoleDiffEngine'),
        ('core.scoring_engine', 'ScoringEngine'),
        ('core.program_policy_parser', 'ProgramPolicyParser'),
        ('core.audit_logger', 'AuditLogger'),
    ]
    
    print("Testing AgentZero109 modules...\n")
    
    success = True
    for module_name, class_name in modules:
        try:
            module = importlib.import_module(module_name)
            getattr(module, class_name)
            print(f"✓ {class_name} imported successfully")
        except ImportError as e:
            print(f"✗ Failed to import {module_name}: {e}")
            success = False
        except AttributeError as e:
            print(f"✗ {class_name} not found in {module_name}: {e}")
            success = False
    
    print()
    if success:
        print("🎉 All modules validated successfully!")
        print("✅ AgentZero109 is ready to use!")
        return 0
    else:
        print("❌ Some modules failed to import")
        print("Run: pip install -r requirements.txt")
        return 1

if __name__ == '__main__':
    sys.exit(test_imports())
