from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

from .common import Finding

SUSPICIOUS = ["curl", "wget", "nc ", "netcat", "bash -c", "python -c", "/tmp/"]
WEAK_PASSWORDS = {"123456", "password", "admin", "qwerty", "letmein", "12345678"}


def scan_suspicious_cron() -> List[Finding]:
    findings: List[Finding] = []
    cron_paths = [Path("/etc/crontab"), Path("/etc/cron.d"), Path("/var/spool/cron")]

    for cp in cron_paths:
        if not cp.exists():
            continue

        files = [cp] if cp.is_file() else [p for p in cp.rglob("*") if p.is_file()]
        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue

            for i, line in enumerate(text.splitlines(), start=1):
                low = line.lower()
                if low.strip().startswith("#") or not low.strip():
                    continue
                if any(tok in low for tok in SUSPICIOUS):
                    findings.append(
                        Finding(
                            module="config_scan",
                            title="Suspicious cron entry",
                            details=f"{f}:{i}: {line.strip()}",
                            severity="HIGH",
                            recommendation="Validate task owner, command intent, and script integrity.",
                        )
                    )
    return findings


def scan_weak_passwords_in_configs(root: Path = Path("/etc"), max_files: int = 10000) -> List[Finding]:
    findings: List[Finding] = []
    checked = 0

    pattern = re.compile(r"(password|passwd|pwd)\s*[:=]\s*([^\s#;]+)", re.IGNORECASE)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"ssl", "pki", "alternatives"}]
        for fn in filenames:
            checked += 1
            if checked > max_files:
                return findings
            f = Path(dirpath) / fn
            try:
                if f.stat().st_size > 1024 * 1024:
                    continue
                text = f.read_text(errors="ignore")
            except Exception:
                continue

            for m in pattern.finditer(text):
                secret = m.group(2).strip("'\"")
                if secret.lower() in WEAK_PASSWORDS or len(secret) < 8:
                    findings.append(
                        Finding(
                            module="config_scan",
                            title="Weak plaintext password found in config",
                            details=f"{f}: value='{secret}'",
                            severity="CRITICAL",
                            recommendation="Use secrets manager/env vars; rotate this credential immediately.",
                        )
                    )
                    break
    return findings


def run_all() -> List[Finding]:
    return scan_suspicious_cron() + scan_weak_passwords_in_configs()
