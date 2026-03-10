"""systemd_scan.py – Audit systemd services and timers for suspicious configurations."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List

from .common import Finding

SUSPICIOUS_EXEC_PATTERNS = re.compile(
    r"(/tmp/|/dev/shm/|curl|wget|nc |netcat|bash -c|python -c|perl -e|"
    r"base64 -d|eval|chmod 777|socat|/bin/sh -i)",
    re.IGNORECASE,
)

UNIT_DIRS = [
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/run/systemd/system"),
]


def _read_unit_files() -> list[tuple[Path, str]]:
    """Return (path, content) for all .service and .timer files."""
    units: list[tuple[Path, str]] = []
    for d in UNIT_DIRS:
        if not d.is_dir():
            continue
        for p in d.rglob("*.service"):
            try:
                units.append((p, p.read_text(errors="ignore")))
            except (PermissionError, OSError):
                pass
        for p in d.rglob("*.timer"):
            try:
                units.append((p, p.read_text(errors="ignore")))
            except (PermissionError, OSError):
                pass
    return units


def scan_suspicious_unit_files() -> List[Finding]:
    """Look for unit files with suspicious ExecStart/ExecStop commands."""
    findings: List[Finding] = []
    for path, text in _read_unit_files():
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("ExecStart", "ExecStop", "ExecReload", "ExecPreStart")):
                if SUSPICIOUS_EXEC_PATTERNS.search(stripped):
                    findings.append(Finding(
                        module="systemd_scan",
                        title="Suspicious ExecStart in systemd unit",
                        details=f"{path}: {stripped[:200]}",
                        severity="HIGH",
                        recommendation="Investigate this unit file. Remove or disable if unauthorized.",
                        evidence={"file": str(path), "exec": stripped[:200]},
                    ))
    return findings


def scan_failed_services() -> List[Finding]:
    """Report services that are in failed state (may indicate tampering or issues)."""
    findings: List[Finding] = []
    try:
        out = subprocess.check_output(
            ["systemctl", "--no-pager", "--failed", "--output=json"],
            text=True, timeout=10, stderr=subprocess.DEVNULL
        )
        import json
        units = json.loads(out)
        for u in units:
            findings.append(Finding(
                module="systemd_scan",
                title=f"Failed systemd service: {u.get('unit', 'unknown')}",
                details=f"Sub-state: {u.get('sub', 'unknown')}",
                severity="LOW",
                recommendation=f"Run `journalctl -u {u.get('unit', '')} -n 50` to investigate.",
                evidence=u,
            ))
    except Exception:
        pass
    return findings


def scan_user_systemd_units() -> List[Finding]:
    """Scan per-user systemd units (can persist as backdoors)."""
    findings: List[Finding] = []
    home_root = Path("/home")

    for user_dir in home_root.iterdir():
        user_systemd = user_dir / ".config" / "systemd" / "user"
        if not user_systemd.is_dir():
            continue
        for unit_file in user_systemd.rglob("*.service"):
            try:
                text = unit_file.read_text(errors="ignore")
            except (PermissionError, OSError):
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("ExecStart") and SUSPICIOUS_EXEC_PATTERNS.search(stripped):
                    findings.append(Finding(
                        module="systemd_scan",
                        title="Suspicious user-level systemd service",
                        details=f"{unit_file}: {stripped[:200]}",
                        severity="HIGH",
                        recommendation="User-level services can persist without root. Remove if unauthorized.",
                        evidence={"file": str(unit_file), "exec": stripped[:200]},
                    ))
            else:
                # Report existence of any user-level services for awareness
                findings.append(Finding(
                    module="systemd_scan",
                    title=f"User-level systemd service found",
                    details=str(unit_file),
                    severity="LOW",
                    recommendation="Verify this user service is intended and legitimate.",
                    evidence={"file": str(unit_file)},
                ))
    return findings


def scan_units_without_sandboxing() -> List[Finding]:
    """Detect high-privilege services missing security hardening directives."""
    findings: List[Finding] = []
    hardening_keys = {"NoNewPrivileges", "PrivateTmp", "ProtectSystem", "ProtectHome"}

    for path, text in _read_unit_files():
        # Only care about services running as root (no User= set, or User=root)
        user_line = next(
            (l for l in text.splitlines() if l.strip().startswith("User=")), ""
        )
        if user_line and "root" not in user_line and "=" in user_line:
            continue  # Non-root service, lower risk

        has_exec = any("ExecStart" in l for l in text.splitlines())
        if not has_exec:
            continue

        missing = [k for k in hardening_keys if k not in text]
        if len(missing) >= 3:  # Missing most hardening directives
            findings.append(Finding(
                module="systemd_scan",
                title=f"Service missing systemd hardening: {path.name}",
                details=f"Missing: {', '.join(missing)}",
                severity="LOW",
                recommendation=(
                    "Add hardening directives: NoNewPrivileges=yes, PrivateTmp=yes, "
                    "ProtectSystem=strict, ProtectHome=yes"
                ),
                evidence={"file": str(path), "missing": missing},
            ))
    return findings[:20]  # Cap to avoid noise


def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [scan_suspicious_unit_files, scan_failed_services,
               scan_user_systemd_units, scan_units_without_sandboxing]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results
