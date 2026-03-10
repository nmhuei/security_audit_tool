"""user_scan.py – Scans local user accounts, sudo config, SSH keys, and bash history."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import List

from .common import Finding

# ─── helpers ──────────────────────────────────────────────────────────────────

SENSITIVE_CMD_PATTERNS = re.compile(
    r"(curl|wget|nc |netcat|chmod 777|python -m http|/tmp/|base64 -d|eval \$|"
    r"bash -i|bash -c|sh -c|rm -rf /|dd if=|mkfs|hexdump)",
    re.IGNORECASE,
)

KNOWN_BAD_SHELLS = {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin"}


# ─── checks ───────────────────────────────────────────────────────────────────

def scan_passwd_accounts() -> List[Finding]:
    """Detect accounts with UID 0 (other than root), empty passwords, or unusual shells."""
    findings: List[Finding] = []
    passwd = Path("/etc/passwd")
    shadow = Path("/etc/shadow")

    if not passwd.exists():
        return findings

    for line in passwd.read_text(errors="ignore").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, pw_field, uid, gid, _, home, shell = parts[:7]

        # Extra UID-0 accounts
        if uid == "0" and user != "root":
            findings.append(Finding(
                module="user_scan",
                title="Non-root account with UID 0",
                details=f"User '{user}' has UID 0 (root equivalent)",
                severity="CRITICAL",
                recommendation=f"Investigate user '{user}'. Remove or change UID unless intentional.",
                evidence={"user": user, "uid": uid},
            ))

        # Empty password in /etc/passwd (legacy style)
        if pw_field == "" and shell not in KNOWN_BAD_SHELLS:
            findings.append(Finding(
                module="user_scan",
                title="Account with empty password field",
                details=f"User '{user}' has blank password in /etc/passwd",
                severity="CRITICAL",
                recommendation="Set a strong password or lock the account with `passwd -l`.",
            ))

    # Check /etc/shadow for accounts with empty passwords or '!' prefix still active
    if shadow.exists():
        try:
            for line in shadow.read_text(errors="ignore").splitlines():
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                user, pw = parts[0], parts[1]
                if pw == "" or pw == "0":
                    findings.append(Finding(
                        module="user_scan",
                        title="Empty shadow password",
                        details=f"User '{user}' has no password set in /etc/shadow",
                        severity="CRITICAL",
                        recommendation=f"Lock account: `passwd -l {user}` or set a password.",
                    ))
        except PermissionError:
            pass

    return findings


def scan_sudo_config() -> List[Finding]:
    """Check sudoers for dangerous NOPASSWD or ALL=(ALL) grants."""
    findings: List[Finding] = []
    sudoers_files = [Path("/etc/sudoers")]
    sudoers_dir = Path("/etc/sudoers.d")
    if sudoers_dir.is_dir():
        sudoers_files += list(sudoers_dir.iterdir())

    nopasswd_re = re.compile(r"NOPASSWD\s*:", re.IGNORECASE)
    allall_re = re.compile(r"ALL\s*=\s*\(ALL\s*\)\s*ALL", re.IGNORECASE)

    for f in sudoers_files:
        try:
            text = f.read_text(errors="ignore")
        except PermissionError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if nopasswd_re.search(stripped):
                findings.append(Finding(
                    module="user_scan",
                    title="NOPASSWD sudo rule detected",
                    details=f"{f}:{i}: {stripped}",
                    severity="HIGH",
                    recommendation="Remove NOPASSWD unless absolutely required; prefer specific commands.",
                    evidence={"file": str(f), "line": i, "rule": stripped},
                ))
            elif allall_re.search(stripped) and not stripped.startswith("root"):
                findings.append(Finding(
                    module="user_scan",
                    title="Broad ALL=(ALL) ALL sudo grant",
                    details=f"{f}:{i}: {stripped}",
                    severity="MEDIUM",
                    recommendation="Restrict sudo to specific commands where possible.",
                ))
    return findings


def scan_ssh_authorized_keys() -> List[Finding]:
    """Find SSH authorized_keys files with unusual attributes."""
    findings: List[Finding] = []
    home_root = Path("/home")
    candidates = list(home_root.glob("*/.ssh/authorized_keys")) + \
                 [Path("/root/.ssh/authorized_keys")]

    for ak in candidates:
        if not ak.exists():
            continue
        try:
            lines = [l for l in ak.read_text(errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
        except PermissionError:
            continue

        for line in lines:
            # Keys with command= options can restrict, but also can be backdoors
            if 'command="' in line and "no-pty" not in line:
                findings.append(Finding(
                    module="user_scan",
                    title="SSH authorized_key with command option",
                    details=f"{ak}: {line[:120]}",
                    severity="MEDIUM",
                    recommendation="Verify this forced-command key belongs to a known user/process.",
                ))
            # Keys from unusual IP/from= constraints
            if "from=" in line:
                findings.append(Finding(
                    module="user_scan",
                    title="SSH key with from= restriction (verify source)",
                    details=f"{ak}: {line[:120]}",
                    severity="LOW",
                    recommendation="Confirm the allowed IP range is intentional and minimal.",
                ))
        # Warn if many keys (possible backdoor accumulation)
        if len(lines) > 20:
            findings.append(Finding(
                module="user_scan",
                title="Large number of SSH authorized keys",
                details=f"{ak} has {len(lines)} keys",
                severity="MEDIUM",
                recommendation="Review and prune any unused or unknown authorized keys.",
            ))
    return findings


def scan_bash_history_anomalies() -> List[Finding]:
    """Check bash/zsh history files for suspicious commands."""
    findings: List[Finding] = []
    history_files: list[Path] = []

    for home in Path("/home").iterdir():
        for hist in [".bash_history", ".zsh_history", ".ash_history"]:
            p = home / hist
            if p.exists():
                history_files.append(p)

    root_hist = Path("/root/.bash_history")
    if root_hist.exists():
        history_files.append(root_hist)

    for hf in history_files:
        try:
            lines = hf.read_text(errors="ignore").splitlines()
        except PermissionError:
            continue
        hits: list[str] = []
        for line in lines:
            if SENSITIVE_CMD_PATTERNS.search(line):
                hits.append(line.strip()[:200])
        if hits:
            findings.append(Finding(
                module="user_scan",
                title="Suspicious commands in shell history",
                details=f"{hf}: {len(hits)} suspicious line(s). First: {hits[0][:120]}",
                severity="MEDIUM",
                recommendation="Review history file for unauthorized activity. Rotate credentials if needed.",
                evidence={"file": str(hf), "count": len(hits), "examples": hits[:3]},
            ))
    return findings


def scan_privileged_groups() -> List[Finding]:
    """Check members of powerful groups: sudo, wheel, docker, adm, shadow."""
    findings: List[Finding] = []
    dangerous_groups = {"docker", "sudo", "wheel", "adm", "shadow", "disk", "lxd"}
    group_file = Path("/etc/group")
    if not group_file.exists():
        return findings

    for line in group_file.read_text(errors="ignore").splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        grp_name, _, _, members_str = parts[:4]
        if grp_name not in dangerous_groups:
            continue
        members = [m for m in members_str.split(",") if m.strip()]
        for m in members:
            sev = "HIGH" if grp_name in {"docker", "disk", "lxd"} else "MEDIUM"
            findings.append(Finding(
                module="user_scan",
                title=f"User in privileged group '{grp_name}'",
                details=f"User '{m}' is member of group '{grp_name}'",
                severity=sev,
                recommendation=f"Verify '{m}' needs '{grp_name}' group access. Remove if unnecessary.",
                evidence={"group": grp_name, "user": m},
            ))
    return findings


def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [scan_passwd_accounts, scan_sudo_config, scan_ssh_authorized_keys,
               scan_bash_history_anomalies, scan_privileged_groups]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results
