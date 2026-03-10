# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v5.x    | ✅ Active  |
| v4.x    | ⚠️ Patches only |
| < v4    | ❌ EOL |

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, report privately via one of:
- GitHub private security advisory (preferred)
- Email: `security@[your-domain].com`

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. (Optional) Suggested fix

We aim to respond within **48 hours** and patch within **7 days** for critical issues.

## Scope

This tool scans the **local machine only**. Acceptable reports include:
- Credential exposure in generated reports
- Arbitrary code execution via malicious config files
- Privilege escalation within the tool itself

Out of scope:
- Issues requiring physical access
- Social engineering
- Findings from scanning your own systems

## Security Design Principles

- No network connections except to OSV/Trivy APIs (CVE data) and Telegram (if configured)
- All secrets in reports are masked (e.g. `sk-ant-...xxxx`)
- No data collection or telemetry
- Reports stored locally only
