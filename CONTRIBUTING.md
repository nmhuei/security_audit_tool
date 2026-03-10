# Contributing to Security Audit Tool

Thank you for considering contributing! This guide will get you up and running quickly.

## Quick Start

```bash
git clone https://github.com/your-username/security-audit-tool.git
cd security-audit-tool
make venv
source .venv/bin/activate
make test         # run all tests
make scan-quick   # quick scan on your machine
```

## How to Contribute

### Reporting Bugs

Open a GitHub Issue with:
- Your OS and Python version
- Steps to reproduce
- Expected vs actual output
- Relevant log output (sanitize any sensitive info)

### Adding a New Scanner Module

1. Create `sat/scanner/your_module.py`
2. Implement a `run_all() -> List[Finding]` function
3. Return `Finding` objects from `scanner.common`
4. Register in `sat/main.py` → `MODULES` dict
5. Write tests in `sat/tests/test_all.py` (minimum 3 test cases)
6. Document in README

**Finding severity guide:**

| Severity | When to use |
|----------|-------------|
| `CRITICAL` | Direct path to root/full compromise |
| `HIGH` | Significant exposure, easy to exploit |
| `MEDIUM` | Requires additional conditions |
| `LOW` | Best practice violation, low impact |

### Improving Existing Modules

- Run `make test-cov` to see coverage gaps
- Focus on modules with < 70% coverage
- Add edge-case tests (empty input, permissions errors, malformed data)

### Pull Request Checklist

- [ ] `make check` passes (lint + tests)
- [ ] New scanner: tests added, module registered, README updated
- [ ] No hardcoded paths (use `Path` objects)
- [ ] Exception handling with graceful degradation
- [ ] Evidence dict populated on every `Finding`

## Code Style

- Python 3.10+ type hints throughout
- `from __future__ import annotations` at top of every file
- Max line length: 120 characters
- Docstrings on all public functions

## Project Structure

```
sat/
├── scanner/      # Individual check modules
├── ai/           # LLM integration (analyzer + providers)
├── reporter/     # HTML report generation
├── telegram/     # Telegram bot integration
├── tests/        # Unit tests
├── main.py       # CLI entry point
├── remediation.py# Auto-fix engine
└── scheduler.py  # Cron/systemd timer management
```

## Security Scope

This tool is **strictly defensive** — local machine scanning only.
Please do **not** submit PRs that:
- Add exploitation or payload capabilities
- Scan remote hosts without explicit opt-in
- Collect or transmit data without user consent

## Questions?

Open a Discussion or Issue on GitHub. We're friendly! 🤝
