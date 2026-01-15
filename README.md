# 🎯 AgentZero109

**Elite AI-Powered Bug Bounty Hunting Framework**

AgentZero109 is NOT a generic vulnerability scanner. It is a precision, high-impact, AI-reasoning–driven bug hunting system whose sole objective is to identify, validate, and package vulnerabilities that historically yield the highest bug bounty payouts.

## 🔥 Core Philosophy

AgentZero109 exists to answer one question only:

**"Which vulnerabilities in this target are most likely to be accepted and paid at the highest bounty tiers?"**

It ignores low-value findings, avoids noisy automation, and behaves like a top 5% human bug bounty hunter augmented with AI.

## 🚀 Key Features

### Intelligent Agent Architecture
- **Recon Agent**: Tech stack identification, endpoint discovery, authentication flow mapping
- **Logic Reasoning Agent** (MOST IMPORTANT): Business logic analysis, state tracking, trust boundary detection
- **Exploit Validation Agent**: Non-destructive validation with canary payloads
- **Chaining Engine**: Combines low-severity issues into high-impact chains
- **Report Agent**: Triager-optimized reports with minimal reproduction steps

### High-Value Vulnerability Focus

**Tier 1 Priorities (Highest ROI):**
- Authorization & Access Control (IDOR, Privilege Escalation, BOLA)
- Business Logic Flaws (Workflow bypass, Double-spend, Order abuse)
- Account Takeover Chains (Password reset poisoning, OAuth misbinding)

**Tier 2 Priorities:**
- SSRF (Cloud-focused metadata access)
- Advanced Injection (Second-order SQLi, Template injection, GraphQL)

### Core Design Principles

✅ **Reason first, send later**  
✅ **Validate twice, report once**  
✅ **Chain small issues into big impact**  
✅ **Exploit logic, not just syntax**  
✅ **Behave like a careful human, not a scanner**

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/scthakurii/AgentZero109.git
cd AgentZero109

# Install dependencies
pip install -r requirements.txt

# Make CLI executable
chmod +x cli/agentzero.py
```

## 🎮 Usage

### Basic Scan

```bash
python cli/agentzero.py -t https://example.com
```

### With Program Policy

```bash
python cli/agentzero.py -t https://example.com -p hackerone_policy.yaml
```

### Autonomous Mode (No Human Review)

```bash
python cli/agentzero.py -t https://example.com --autonomous
```

### Custom Rate Limit

```bash
python cli/agentzero.py -t https://example.com -r 5
```

## 🏗️ Architecture

```
AgentZero109/
├── agents/              # Specialized hunting agents
│   ├── recon_agent.py
│   ├── logic_agent.py   # ⭐ Most important
│   ├── exploit_agent.py
│   ├── chain_agent.py
│   └── report_agent.py
├── core/                # Core infrastructure
│   ├── state_tracker.py
│   ├── role_diff_engine.py
│   ├── scoring_engine.py
│   ├── program_policy_parser.py
│   └── audit_logger.py
├── cli/
│   └── agentzero.py     # Main CLI
└── templates/           # Vulnerability templates
    ├── idor.yaml
    ├── auth_bypass.yaml
    ├── ssrf_cloud.yaml
    └── business_logic.yaml
```

## 🔒 Safety Controls

AgentZero109 includes strict safety mechanisms:

- ✅ **Rate Limiting**: Automatic request throttling
- ✅ **Kill Switch**: Emergency stop capability
- ✅ **Audit Logging**: Full audit trail of all operations
- ✅ **Non-Destructive Testing**: Canary-based validation
- ✅ **Human-in-the-Loop Mode**: Optional manual review

## 🎯 What AgentZero109 Does

✅ Identifies high-payout vulnerabilities  
✅ Analyzes business logic and state transitions  
✅ Validates findings with controlled exploitation  
✅ Chains vulnerabilities for maximum impact  
✅ Generates triager-optimized reports  
✅ Learns from program-specific feedback  

## ❌ What AgentZero109 Does NOT Do

❌ Destructive actions (deletes, payments, irreversible writes)  
❌ Denial-of-service testing  
❌ Scanning out-of-scope assets  
❌ Blind mass fuzzing without reasoning  
❌ Chasing low-impact vulnerabilities  
❌ Operating without strict rate control  
❌ Submitting findings without confidence validation  

## 📊 Scoring System

Every finding is scored on:

- **Impact Score** (0-10)
- **Exploitability** (Low/Medium/High)
- **Confidence** (Low/Medium/High)
- **Estimated Bounty Range**
- **Duplicate Likelihood**

Only findings exceeding a high-confidence threshold proceed to reporting.

## 🧠 Logic Reasoning Agent

The Logic Reasoning Agent is the brain of AgentZero109. It asks:

- "What happens if steps are skipped?"
- "What happens if steps are reordered?"
- "What happens if steps are repeated?"
- "What happens if parameters are manipulated?"

This is where the magic happens.

## 🔗 Vulnerability Chaining

AgentZero109 automatically identifies exploit chains:

- Information Disclosure → Account Takeover
- XSS → Session Token Theft → ATO
- Multiple IDORs → Privilege Escalation
- SSRF → Cloud Metadata Access
- Business Logic Bypass → Financial Manipulation

## 📝 Report Generation

Reports include:

- Minimal reproduction steps
- Clear before/after behavior
- Business impact explanation
- Curl commands or HTTP traces
- Screenshots or artifacts where applicable

## 🌟 Examples

### IDOR Detection

```python
from agents.logic_agent import LogicReasoningAgent

agent = LogicReasoningAgent("https://example.com")
findings = await agent.analyze_authorization(
    endpoints=[{"url": "/api/user/123", "method": "GET"}],
    roles=["admin", "user"]
)
```

### Business Logic Analysis

```python
workflow = [
    {"name": "add_to_cart", "endpoint": "/api/cart", "method": "POST"},
    {"name": "apply_discount", "endpoint": "/api/discount", "method": "POST"},
    {"name": "checkout", "endpoint": "/api/checkout", "method": "POST"}
]

findings = await agent.analyze_workflow("checkout_flow", workflow)
```

## 🤝 Contributing

This is a specialized bug bounty hunting framework. Contributions should focus on:

- New high-value vulnerability detection techniques
- Improved logic reasoning capabilities
- Better chain detection patterns
- Program-specific adaptations

## ⚖️ Legal & Ethical Use

AgentZero109 is designed for:

- ✅ Authorized bug bounty programs
- ✅ Penetration testing with written permission
- ✅ Security research on your own systems

**NEVER:**

- ❌ Test without authorization
- ❌ Exceed program scope
- ❌ Perform destructive actions
- ❌ Ignore program rules

## 📄 License

See DISCLAIMER.md for usage terms.

## 🙏 Credits

Built with:
- Python 3.8+
- aiohttp (async HTTP)
- Rich (beautiful CLI)
- Jinja2 (report templating)
- PyYAML (configuration)

---

**AgentZero109: Quiet, Precise, Ethical, Controlled, and Lethal in Impact.**

For questions or issues, please open a GitHub issue.
