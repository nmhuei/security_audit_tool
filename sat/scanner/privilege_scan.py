from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Iterable, List

from .common import Finding

SSH_CONFIG = Path("/etc/ssh/sshd_config")


def scan_weak_ssh_config() -> List[Finding]:
    findings: List[Finding] = []
    if not SSH_CONFIG.exists():
        return findings

    raw = SSH_CONFIG.read_text(errors="ignore")
    checks = {
        "PermitRootLogin yes": ("HIGH", "Set PermitRootLogin no or prohibit-password."),
        "PasswordAuthentication yes": ("MEDIUM", "Prefer key-based auth; set PasswordAuthentication no."),
        "Protocol 1": ("CRITICAL", "Use Protocol 2 only."),
    }
    for key, (sev, rec) in checks.items():
        if re.search(rf"^\s*{re.escape(key)}\s*$", raw, re.MULTILINE):
            findings.append(Finding("privilege_scan", f"Weak SSH setting: {key}", f"Found '{key}' in {SSH_CONFIG}", sev, rec))
    return findings


def _walk_secure(paths: Iterable[Path], max_files: int = 200000):
    count = 0
    for root in paths:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d not in {"proc", "sys", "dev", "run", ".git", "node_modules"}]
            for fn in filenames:
                p = Path(dirpath) / fn
                yield p
                count += 1
                if count >= max_files:
                    return


def scan_suid_sgid(paths: Iterable[Path] | None = None) -> List[Finding]:
    paths = paths or [Path("/bin"), Path("/usr/bin"), Path("/usr/local/bin"), Path("/sbin"), Path("/usr/sbin")]
    findings: List[Finding] = []
    for p in _walk_secure(paths):
        try:
            mode = p.lstat().st_mode
            if mode & stat.S_ISUID or mode & stat.S_ISGID:
                findings.append(
                    Finding(
                        module="privilege_scan",
                        title="SUID/SGID binary found",
                        details=str(p),
                        severity="MEDIUM",
                        recommendation="Validate necessity; remove special bits from unneeded binaries.",
                        evidence={"path": str(p), "mode": oct(mode)},
                    )
                )
        except OSError:
            continue
    return findings


def scan_privileged_processes() -> List[Finding]:
    findings: List[Finding] = []
    try:
        out = subprocess.check_output(["ps", "-eo", "user,pid,comm,args"], text=True, timeout=8)
    except Exception:
        return findings

    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        if line.startswith("root") and any(k in line.lower() for k in ["python -m http.server", "nc ", "netcat", "socat", "bash -c"]):
            findings.append(
                Finding(
                    module="privilege_scan",
                    title="Potentially risky root process",
                    details=line.strip(),
                    severity="HIGH",
                    recommendation="Review root-owned process and limit privileges/service account.",
                )
            )
    return findings


def run_all() -> List[Finding]:
    return scan_weak_ssh_config() + scan_suid_sgid() + scan_privileged_processes()
