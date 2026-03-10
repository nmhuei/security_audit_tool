<div align="center">

# 🔒 Security Audit Tool

**A professional, modular Linux security scanner with AI-powered analysis**

[![CI](https://github.com/nmhuei/security_audit_tool/actions/workflows/ci.yml/badge.svg)](https://github.com/nmhuei/security_audit_tool/actions)
[![Coverage](https://codecov.io/gh/nmhuei/security_audit_tool/branch/main/graph/badge.svg)](https://codecov.io/gh/nmhuei/security_audit_tool)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) · [Install](#installation) · [Usage](#usage) · [Modules](#scanner-modules) · [Contributing](../CONTRIBUTING.md)

</div>

---

## What is this?

Security Audit Tool (SAT) is a **defensive** local security scanner for Linux machines.
It runs entirely on your machine, reports what it finds, and optionally auto-fixes safe issues.

```
╔══════════════════════════════════════════════════════╗
║           SECURITY AUDIT REPORT                     ║
╚══════════════════════════════════════════════════════╝

  🔴  Overall Posture : HIGH RISK
  📊  Risk Score     : 47
  🔍  Total Findings : 18

  Severity Breakdown:
    CRITICAL    2  ██
    HIGH        5  █████
    MEDIUM      7  ███████
    LOW         4  ████

  🤖  AI Analysis [claude-3-5-sonnet]:
  ─────────────────────────────────────
  1. Risk Summary: Redis (6379) and MongoDB (27017) are exposed on
     all interfaces with no firewall — immediate remote compromise risk.
  2. Most Dangerous Chain: Redis SSRF → write cron → root shell...
```

## Features

| Feature | Details |
|---------|---------|
| 🔍 **11 scanner modules** | Ports, privileges, filesystem, secrets, CVEs, Docker, systemd, users, config |
| 🤖 **AI analysis** | Risk summary + attack chains via Claude, GPT-4, Ollama, or Gemini |
| 📈 **Baseline & drift** | Snapshot findings, compare over time, detect regressions |
| 🔧 **Auto-remediation** | `--fix` / `--dry-run` for safe automated fixes |
| 📊 **Rich reports** | Terminal dashboard, HTML report, JSON output |
| 📱 **Telegram alerts** | Bot polling (`/scan`, `/report`) or one-shot alerts |
| ⏰ **Scheduler** | systemd timer or cron integration |
| 🔑 **Secret detection** | Shannon entropy + 15 pattern types (AWS, GitHub, OpenAI, ...) |

## Installation

```bash
git clone https://github.com/nmhuei/security_audit_tool.git
cd security_audit_tool

# Option A: Make (recommended)
make venv
source .venv/bin/activate

# Option B: Manual
python3 -m venv .venv && source .venv/bin/activate
pip install -r sat/requirements.txt
```

**Optional: Install external tools for deeper scans**
```bash
sudo apt-get install lynis nmap chkrootkit rkhunter trivy aide nikto
```

## Usage

### Basic scan
```bash
cd sat
python3 main.py scan
```

### Deep scan (slower, more thorough)
```bash
python3 main.py scan --deep
```

### Auto-fix safe issues
```bash
python3 main.py scan --fix --dry-run   # preview
python3 main.py scan --fix             # apply
```

### Baseline & drift detection
```bash
python3 main.py scan --save-baseline   # save snapshot
# ... after changes ...
python3 main.py diff                   # see what changed
```

### Telegram integration
```bash
# One-shot alert
python3 main.py telegram --token "BOT_TOKEN" --chat-id "CHAT_ID" --mode once

# Interactive bot (/scan, /report)
python3 main.py telegram --token "BOT_TOKEN" --chat-id "CHAT_ID" --mode poll
```

### Schedule periodic scans
```bash
python3 main.py schedule install --freq daily   # systemd timer
python3 main.py schedule install --backend cron # or cron
python3 main.py schedule status
```

### All CLI options
```
python3 main.py scan --help
python3 main.py --help
```

## Scanner Modules

| Module | What it checks |
|--------|---------------|
| `port_scanner` | Open ports + banner grabbing (50+ ports) |
| `privilege_scan` | SUID/SGID binaries, capabilities, sudo misconfig |
| `filesystem_scan` | World-writable files, sensitive file permissions |
| `network_scan` | Firewall, ARP spoofing, promiscuous interfaces, IP forwarding |
| `cve_scan` | CVEs via Trivy → Ubuntu USN → OSV (with rate limiting) |
| `config_scan` | SSH hardening, kernel sysctl, PAM settings |
| `user_scan` | UID-0 accounts, empty passwords, sudo rules, bash history |
| `secret_scan` | Credentials in files (entropy + 15 patterns) |
| `systemd_scan` | Suspicious systemd unit ExecStart commands |
| `docker_scan` | Docker socket, privileged containers, daemon config |
| `kali_tools` | lynis, nmap, rkhunter, chkrootkit, nikto, AIDE |

## AI Providers

Configure in `.env` or environment variables:

```bash
# Anthropic (recommended)
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
OPENAI_API_KEY=sk-...

# Ollama (local, free)
OLLAMA_HOST=http://localhost:11434

# Google Gemini
GOOGLE_API_KEY=...
```

## Development

```bash
make test        # run all tests
make test-cov    # tests + coverage report
make lint        # flake8 lint
make check       # lint + tests combined
make help        # show all make targets
```

## Safety Guarantees

- ✅ Scans **local machine only** — no remote targets
- ✅ No exploitation or payload modules
- ✅ Secrets in reports are **masked** (`sk-ant-...xxxx`)
- ✅ No telemetry or data collection
- ✅ Reports stored locally only

## License

MIT © 2024 — see [LICENSE](../LICENSE)

---

<div align="center">
<sub>If this tool helped secure your system, consider giving it a ⭐</sub>
</div>
