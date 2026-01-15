# AgentZero109 Usage Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Usage](#basic-usage)
3. [Advanced Usage](#advanced-usage)
4. [Agent Details](#agent-details)
5. [Configuration](#configuration)
6. [Interpreting Results](#interpreting-results)
7. [Best Practices](#best-practices)

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/scthakurii/AgentZero109.git
cd AgentZero109

# Run setup script
./setup.sh

# Or manual setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### First Scan

```bash
# Basic scan
python cli/agentzero.py -t https://example.com

# With verbose output
python cli/agentzero.py -t https://example.com -v
```

## Basic Usage

### Target Specification

```bash
# Single target
agentzero -t https://api.example.com

# With subdomain
agentzero -t https://app.example.com/api/v1
```

### Rate Limiting

```bash
# Default (10 req/s)
agentzero -t https://example.com

# Custom rate (5 req/s)
agentzero -t https://example.com -r 5

# Aggressive (20 req/s) - use with caution
agentzero -t https://example.com -r 20
```

### Output Control

```bash
# Save to specific directory
agentzero -t https://example.com --output-dir ./my_results

# JSON format only
agentzero -t https://example.com --format json

# Include all verbosity
agentzero -t https://example.com -v
```

## Advanced Usage

### Program Policy Integration

Create a program policy file:

```yaml
# my_program.yaml
program_name: "My Bug Bounty Program"
scope:
  in_scope_domains:
    - example.com
    - api.example.com
  out_of_scope:
    - blog.example.com
  excluded_types:
    - self_xss
    - clickjacking
```

Use it:

```bash
agentzero -t https://example.com -p my_program.yaml
```

### Human-in-the-Loop vs Autonomous

```bash
# Default: Human review mode
agentzero -t https://example.com

# Autonomous mode (no prompts)
agentzero -t https://example.com --autonomous

# Dry run (no actual requests)
agentzero -t https://example.com --dry-run
```

### Focusing on Specific Vulnerabilities

```bash
# Focus on IDOR
agentzero -t https://example.com --focus idor

# Focus on business logic
agentzero -t https://example.com --focus business_logic

# Multiple focuses
agentzero -t https://example.com --focus idor,ssrf,privilege_escalation
```

## Agent Details

### 1. Recon Agent

**Purpose**: Gather intelligence about the target

**What it does**:
- Identifies technology stack
- Discovers endpoints
- Maps authentication flows
- Detects cloud providers
- Identifies API types (REST, GraphQL, etc.)

**Output**: Technology fingerprints, endpoint list, auth flow map

### 2. Logic Reasoning Agent ⭐ (Most Important)

**Purpose**: Analyze business logic and state transitions

**What it does**:
- Tests workflow bypasses
- Analyzes parameter manipulation
- Checks state validation
- Compares role-based access
- Identifies trust boundary issues

**Output**: Business logic vulnerabilities, workflow bypasses, state violations

### 3. Exploit Validation Agent

**Purpose**: Confirm vulnerabilities with non-destructive testing

**What it does**:
- Uses canary payloads
- Time-based validation
- Out-of-band callbacks
- Cross-user access tests
- Eliminates false positives

**Output**: Validated findings with evidence

### 4. Chaining Engine

**Purpose**: Combine vulnerabilities for maximum impact

**What it does**:
- Builds attack graphs
- Identifies exploit chains
- Calculates combined severity
- Estimates bounty increases

**Output**: Exploit chains with narratives

### 5. Report Agent

**Purpose**: Generate professional vulnerability reports

**What it does**:
- Creates triager-optimized reports
- Minimal reproduction steps
- Business impact analysis
- Curl commands and HTTP logs

**Output**: Markdown/JSON reports ready for submission

## Configuration

### Default Configuration

Location: `config/default_config.yaml`

Key settings:

```yaml
# Rate limiting
rate_limiting:
  default_rate: 10
  burst_size: 20

# Agent enablement
agents:
  recon:
    enabled: true
  logic:
    enabled: true
  exploit:
    enabled: true

# Safety
safety:
  human_review_mode: true
  kill_switch_enabled: true
```

### Custom Configuration

Create your own config:

```yaml
# my_config.yaml
rate_limiting:
  default_rate: 5

agents:
  recon:
    deep_scan: true
  logic:
    max_workflow_depth: 10
```

Use it:

```bash
agentzero -t https://example.com -c my_config.yaml
```

## Interpreting Results

### Severity Levels

- **Critical**: Immediate high-value submission ($5k-$50k potential)
- **High**: Strong finding ($1k-$10k potential)
- **Medium**: Moderate impact ($250-$2k potential)
- **Low**: Informational/minimal impact

### Confidence Levels

- **High**: Validated with proof, submit immediately
- **Medium**: Likely valid, review before submission
- **Low**: Needs more validation, investigate further

### Priority Score

Scale: 0-10

- **9-10**: Submit immediately, highest priority
- **7-8**: Review and submit
- **5-6**: Investigate further
- **<5**: Low priority, may not be worth submission

### Report Structure

Generated reports include:

1. **Title**: Clear, descriptive vulnerability name
2. **Summary**: Executive summary
3. **Business Impact**: Why it matters
4. **Reproduction Steps**: Minimal steps to reproduce
5. **Evidence**: HTTP logs, screenshots, etc.
6. **Remediation**: Fix recommendations

## Best Practices

### 1. Always Use Program Policies

```bash
agentzero -t https://example.com -p program_policy.yaml
```

Benefits:
- Respects scope
- Avoids excluded vulnerability types
- Optimizes for program-specific payouts

### 2. Start with Human Review Mode

```bash
# First scan - review findings
agentzero -t https://example.com

# After understanding behavior - autonomous
agentzero -t https://example.com --autonomous
```

### 3. Respect Rate Limits

```bash
# Start conservative
agentzero -t https://example.com -r 5

# Increase if no issues
agentzero -t https://example.com -r 10
```

### 4. Review Audit Logs

After each scan:

```bash
# Check audit logs
cat audit_logs/audit_*.jsonl | jq
```

### 5. Focus on High-Value Targets

Priority order:
1. Business logic vulnerabilities
2. Authorization issues (IDOR, privilege escalation)
3. Account takeover chains
4. Cloud SSRF
5. Advanced injection

### 6. Chain Findings

Look for opportunities to chain:
- Info disclosure + weak password reset = ATO
- Multiple IDORs = privilege escalation
- SSRF + cloud metadata = credential theft

### 7. Validate Before Submitting

Always review:
- Reproduction steps work
- Impact is clearly demonstrated
- Evidence is complete
- No false positives

## Common Workflows

### Workflow 1: New Target Assessment

```bash
# 1. Basic recon
agentzero -t https://example.com --phase recon

# 2. Full assessment
agentzero -t https://example.com

# 3. Review results
cat reports/summary_*.md
```

### Workflow 2: Focused Testing

```bash
# Test specific vulnerability type
agentzero -t https://example.com --focus idor

# Review IDOR findings
cat findings/idor_*.json
```

### Workflow 3: Program-Specific Hunt

```bash
# 1. Create program policy
cat > program.yaml << EOF
program_name: "Target Program"
scope:
  in_scope_domains: [example.com]
payout_info:
  accepted_vulnerabilities:
    business_logic: 30
    idor: 25
EOF

# 2. Run optimized scan
agentzero -t https://example.com -p program.yaml

# 3. Focus on highest-paying types
agentzero -t https://example.com -p program.yaml --focus business_logic,idor
```

## Troubleshooting

### Issue: Too many false positives

**Solution**: Increase confidence threshold

```bash
agentzero -t https://example.com --min-confidence high
```

### Issue: Scan too slow

**Solution**: Increase rate limit (carefully)

```bash
agentzero -t https://example.com -r 15
```

### Issue: Getting blocked

**Solution**: Decrease rate limit, add delays

```bash
agentzero -t https://example.com -r 3 --delay 1
```

### Issue: Missing vulnerabilities

**Solution**: Enable deep scan

```bash
agentzero -t https://example.com --deep-scan
```

## Output Files

### Directory Structure

```
AgentZero109/
├── reports/              # Human-readable reports
│   ├── summary_*.md
│   └── finding_*.md
├── findings/             # JSON findings data
│   ├── critical_*.json
│   └── high_*.json
├── audit_logs/           # Audit trail
│   └── audit_*.jsonl
└── evidence/             # Evidence files
    ├── http_logs/
    └── screenshots/
```

### File Formats

**Reports (Markdown)**:
- Complete vulnerability write-ups
- Ready for submission
- Include all evidence

**Findings (JSON)**:
- Structured vulnerability data
- Programmatic access
- Integration-friendly

**Audit Logs (JSONL)**:
- One event per line
- Full operation history
- Compliance/debugging

## Safety Features

### Kill Switch

Press `Ctrl+C` at any time to stop

### Rate Limiting

Automatic throttling prevents DoS

### Audit Logging

Every action is logged for accountability

### Non-Destructive Testing

All validation uses safe methods:
- Canary payloads (UUIDs)
- Time-based detection
- Out-of-band callbacks
- Read-only operations

## Getting Help

```bash
# Show help
agentzero --help

# Show version
agentzero --version

# Show agent info
agentzero --list-agents

# Show vulnerability templates
agentzero --list-templates
```

## Legal & Ethical Considerations

⚠️ **IMPORTANT**: Only use AgentZero109 on:
- Bug bounty programs you're authorized to test
- Systems you own
- Systems with written permission

Never:
- Test without authorization
- Exceed program scope
- Perform destructive actions
- Exfiltrate real user data

---

For more information, see [README.md](README.md) or open a GitHub issue.
