# Changelog

All notable changes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [5.0.0] – 2024-12

### Added
- **Baseline & drift detection** – snapshot findings and compare over time
- **Auto-remediation engine** (`--fix`, `--dry-run`) with safe-only mode
- **AI analysis** with multi-provider support (Anthropic, OpenAI, Ollama, Gemini)
- **System context** enrichment in AI prompts (kernel, services, users, firewall)
- **HTML reports** with interactive dashboard
- **Telegram bot** – polling mode + one-shot alerts
- **Systemd/cron scheduler** for periodic scans
- **Docker security audit** – socket, privileged containers, daemon config
- **systemd unit file scanner** – suspicious ExecStart detection
- **Secret scanner** – Shannon entropy + allowlist, 15 secret patterns
- **Kali tools integration** – lynis, nmap, rkhunter, chkrootkit, nikto, AIDE
- **User audit** – UID 0 accounts, passwordless users, sudo misconfig, bash history
- `--deep` mode for thorough scans (nmap vuln scripts, rkhunter, tiger, aide)
- `--skip MODULE` to exclude modules from scan
- Rich terminal dashboard with scan progress

### Changed
- CVE scanning: Trivy primary → Ubuntu USN → OSV fallback chain
- OSV API uses batch endpoint (50 packages per request) with rate limiting
- Port scanner expanded to 50+ ports with banner grabbing

### Fixed
- Module timeout now per-module (not global)
- Baseline diff correctly handles evidence field changes

## [4.x] – 2024-06

### Added
- Initial CVE scanning via OSV API
- Basic port scanner and privilege escalation checks
- SSH config auditing
- JSON + text report output

## [3.x] – 2024-01

### Added
- First public release
- Port scanning, SUID checks, world-writable files, cron jobs
