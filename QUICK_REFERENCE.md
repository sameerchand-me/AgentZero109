# AgentZero109 Quick Reference

## 🚀 Quick Start

```bash
# Setup
./setup.sh
source venv/bin/activate

# Basic scan
python cli/agentzero.py -t https://example.com

# With policy
python cli/agentzero.py -t https://example.com -p config/example_program.yaml
```

## 📋 Command Cheat Sheet

```bash
# Basic Usage
agentzero -t <URL>                    # Basic scan
agentzero -t <URL> -v                 # Verbose
agentzero -t <URL> --autonomous       # No prompts
agentzero -t <URL> --dry-run          # Simulate only

# Rate Control
agentzero -t <URL> -r 5               # 5 req/sec
agentzero -t <URL> -r 10              # 10 req/sec (default)
agentzero -t <URL> -r 20              # 20 req/sec (aggressive)

# With Policy
agentzero -t <URL> -p policy.yaml     # Use program policy
agentzero -t <URL> -c config.yaml     # Custom config
```

## 🎯 Vulnerability Priorities

### Tier 1 (Focus Here) 💰💰💰
- IDOR / BOLA
- Privilege Escalation
- Business Logic Bypass
- Account Takeover
- Workflow Bypass
- Double-Spend / Replay
- Parameter Manipulation

### Tier 2 (High Value) 💰💰
- SSRF (Cloud-focused)
- Second-order SQLi
- Template Injection
- GraphQL Injection

### Ignored (Low Value) ❌
- Basic XSS
- Clickjacking
- Self-XSS
- Missing Headers
- Banner Disclosure

## 🧠 Logic Agent Questions

The Logic Agent asks:
- "What if this step is skipped?"
- "What if steps are reordered?"
- "What if this step is repeated?"
- "What if this parameter is manipulated?"

## 📊 Severity Matrix

| Severity | Impact | Confidence | Action |
|----------|--------|------------|--------|
| Critical | 9-10   | High       | Submit Now |
| High     | 7-8    | High       | Review & Submit |
| Medium   | 4-6    | Medium+    | Investigate |
| Low      | 1-3    | Any        | Skip |

## 🔍 Testing Workflows

### IDOR Testing
```python
1. User1 creates resource → Note ID
2. User2 tries to access User1's ID
3. Success = IDOR confirmed
```

### Business Logic
```python
1. Map complete workflow
2. Try skipping steps
3. Try reordering steps
4. Manipulate parameters
5. Repeat actions (replay)
```

### Authorization
```python
1. Test endpoint as Admin → 200
2. Test endpoint as User → 200?
3. Compare responses
4. Check for data leakage
```

## 📁 Output Files

```
reports/          # Markdown reports (submit these)
findings/         # JSON data (for processing)
audit_logs/       # Full audit trail (compliance)
```

## 🛡️ Safety Controls

| Control | Purpose | How to Use |
|---------|---------|------------|
| Rate Limit | Prevent DoS | `-r <num>` |
| Kill Switch | Emergency stop | `Ctrl+C` |
| Audit Log | Accountability | Auto-enabled |
| Human Review | Manual check | Default mode |
| Dry Run | Test without requests | `--dry-run` |

## ⚡ Best Practices

✅ **DO:**
- Start with program policy
- Use human review mode first
- Respect rate limits
- Focus on Tier 1 vulnerabilities
- Validate before submitting
- Review audit logs

❌ **DON'T:**
- Test without authorization
- Exceed program scope
- Perform destructive actions
- Submit without validation
- Chase low-value bugs
- Ignore rate limits

## 🔗 Chaining Patterns

```
Info Leak → Password Reset = ATO
XSS → Session Token = ATO
Multiple IDORs = Privilege Escalation
SSRF → Cloud Metadata = Credential Theft
Logic Bypass → Payment = Financial Impact
```

## 📝 Report Checklist

Before submitting:
- [ ] Clear reproduction steps
- [ ] Business impact explained
- [ ] Evidence included
- [ ] Validated (not FP)
- [ ] Within scope
- [ ] High confidence

## 🎨 Agent Overview

| Agent | Purpose | Key Output |
|-------|---------|------------|
| Recon | Intel gathering | Tech stack, endpoints |
| Logic | Business logic | Workflow bypasses ⭐ |
| Exploit | Validation | Confirmed findings |
| Chain | Impact amplification | Exploit chains |
| Report | Documentation | Submission reports |

## 💡 Pro Tips

1. **Focus on Business Logic** - Highest ROI
2. **Chain Vulnerabilities** - Low → Critical
3. **Use Program Policies** - Optimize for payouts
4. **Validate Everything** - No false positives
5. **Professional Reports** - Triager-optimized

## 🚨 Emergency Stop

```
Press Ctrl+C at any time
→ Kill switch activated
→ Operations halted
→ Audit log saved
```

## 📞 Getting Help

```bash
agentzero --help              # Show all options
agentzero --list-agents       # Show agents
agentzero --list-templates    # Show templates
```

See full docs:
- [README.md](README.md) - Overview
- [USAGE.md](USAGE.md) - Detailed guide
- [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) - Implementation

## 🎯 Success Formula

```
High-Value Target
+ Program Policy
+ Logic Reasoning
+ Validation
+ Chaining
+ Professional Report
= Maximum Bounty
```

---

**AgentZero109: Quiet, Precise, Ethical, Controlled, Lethal in Impact** 🎯
