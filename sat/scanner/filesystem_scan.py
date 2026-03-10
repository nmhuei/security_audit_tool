"""filesystem_scan.py – Fast, thorough filesystem security checks using find(1) + targeted walks."""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import List

from .common import Finding

# ── Helpers ────────────────────────────────────────────────────────────────────

SCAN_ROOTS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
              "/usr/local/bin", "/home", "/root", "/var", "/tmp", "/opt"]

EXCLUDE_FIND = [
    "-path", "/proc", "-prune", "-o",
    "-path", "/sys",  "-prune", "-o",
    "-path", "/dev",  "-prune", "-o",
    "-path", "/run",  "-prune", "-o",
]


def _run_find(*args: str, timeout: int = 60) -> list[str]:
    """Run find(1) and return list of paths – much faster than os.walk for large trees."""
    cmd = ["find", "/"] + list(args)
    try:
        out = subprocess.check_output(
            cmd, text=True, timeout=timeout,
            stderr=subprocess.DEVNULL
        )
        return [l.strip() for l in out.strip().splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


# ── 1. World-writable files (fast via find) ───────────────────────────────────

def scan_world_writable(max_findings: int = 200) -> List[Finding]:
    """Find world-writable files using find -perm, skipping virtual FSes."""
    findings: List[Finding] = []

    paths = _run_find(
        "-path", "/proc", "-prune", "-o",
        "-path", "/sys",  "-prune", "-o",
        "-path", "/dev",  "-prune", "-o",
        "-not", "-type", "l",          # skip symlinks
        "-perm", "-0002",              # world-writable
        "-print",
        timeout=45,
    )

    # Legitimately world-writable paths
    EXPECTED_WW = {
        "/tmp", "/var/tmp", "/dev/shm",
        "/run/lock", "/var/lock",
    }

    for p in paths[:max_findings]:
        path = Path(p)
        if any(str(path).startswith(e) for e in EXPECTED_WW):
            continue
        try:
            mode = path.lstat().st_mode
            is_sticky = bool(mode & stat.S_ISVTX)
            # Directory with sticky bit is OK (like /tmp itself)
            if path.is_dir() and is_sticky:
                continue
            findings.append(Finding(
                module="filesystem_scan",
                title="World-writable file" + (" (no sticky bit)" if path.is_dir() else ""),
                details=str(path),
                severity="HIGH" if not is_sticky else "MEDIUM",
                recommendation=f"chmod o-w {path}" + (" (or add sticky bit: chmod +t)" if path.is_dir() else ""),
                evidence={"path": str(path), "mode": oct(mode), "sticky": is_sticky},
            ))
        except OSError:
            continue
    return findings


# ── 2. SUID/SGID outside expected set ─────────────────────────────────────────

EXPECTED_SUID = {
    "/bin/su", "/bin/sudo", "/usr/bin/sudo", "/bin/mount", "/bin/umount",
    "/usr/bin/passwd", "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/sbin/pppd", "/sbin/unix_chkpwd", "/usr/bin/at",
    "/usr/bin/crontab", "/bin/ping", "/usr/bin/ping",
}

def scan_unexpected_suid(max_findings: int = 50) -> List[Finding]:
    """Find SUID/SGID files outside the expected set."""
    findings: List[Finding] = []

    paths = _run_find(
        "-path", "/proc", "-prune", "-o",
        "-path", "/sys",  "-prune", "-o",
        "-perm", "/6000",              # SUID or SGID
        "-type", "f",
        "-print",
        timeout=45,
    )

    for p in paths[:max_findings]:
        path = Path(p)
        if str(path) in EXPECTED_SUID:
            continue
        try:
            mode = path.lstat().st_mode
            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)
            kind = "SUID" if has_suid else "SGID"
            findings.append(Finding(
                module="filesystem_scan",
                title=f"Unexpected {kind} binary: {path.name}",
                details=str(path),
                severity="HIGH",
                recommendation=(
                    f"Verify {path} needs {kind}. If not: "
                    f"chmod u-s {path}" if has_suid else f"chmod g-s {path}"
                ),
                evidence={"path": str(path), "mode": oct(mode), "suid": has_suid, "sgid": has_sgid},
            ))
        except OSError:
            continue
    return findings


# ── 3. Immutable file check ────────────────────────────────────────────────────

SENSITIVE_IMMUTABLE_CHECK = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
    "/etc/crontab", "/etc/ssh/sshd_config", "/etc/fstab",
]

def scan_immutable_attributes() -> List[Finding]:
    """Check file immutable flags – both missing (should be immutable) and unexpected."""
    findings: List[Finding] = []
    try:
        out = subprocess.check_output(
            ["lsattr"] + SENSITIVE_IMMUTABLE_CHECK,
            text=True, timeout=10, stderr=subprocess.DEVNULL
        )
    except Exception:
        return findings

    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        attrs, filepath = parts[0], parts[1]
        # 'i' flag = immutable
        is_immutable = "i" in attrs
        if not is_immutable:
            # Not flagging missing immutable as an issue – just informational
            pass
        # 'a' flag = append-only (can hide malicious writes to logs)
        if "a" not in attrs and filepath.startswith("/var/log"):
            pass
        # 'e' flag absent on /etc/shadow means ext4 extents not used – unusual
    return findings   # informational, return empty for now – can extend


# ── 4. Misconfigured permissions on sensitive files ───────────────────────────

SENSITIVE_FILES = {
    "/etc/passwd":          (0o644, "MEDIUM", "Set to 644: chmod 644 /etc/passwd"),
    "/etc/shadow":          (0o640, "CRITICAL", "Set to 640, owned root:shadow: chmod 640 /etc/shadow && chown root:shadow /etc/shadow"),
    "/etc/gshadow":         (0o640, "HIGH", "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow"),
    "/etc/sudoers":         (0o440, "CRITICAL", "chmod 440 /etc/sudoers — only root should read"),
    "/etc/ssh/sshd_config": (0o600, "HIGH", "chmod 600 /etc/ssh/sshd_config"),
    "/boot/grub/grub.cfg":  (0o600, "MEDIUM", "chmod 600 /boot/grub/grub.cfg"),
    "/etc/crontab":         (0o600, "MEDIUM", "chmod 600 /etc/crontab"),
}

def scan_misconfigured_permissions() -> List[Finding]:
    findings: List[Finding] = []
    for filepath, (expected_mode, severity, rec) in SENSITIVE_FILES.items():
        p = Path(filepath)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode & 0o777
            if mode != expected_mode:
                findings.append(Finding(
                    module="filesystem_scan",
                    title=f"Wrong permissions on {filepath}",
                    details=f"Current: {oct(mode)} | Expected: {oct(expected_mode)}",
                    severity=severity,
                    recommendation=rec,
                    evidence={"path": filepath, "current": oct(mode), "expected": oct(expected_mode)},
                ))
        except OSError:
            continue
    return findings


# ── 5. /tmp and /dev/shm suspicious files ────────────────────────────────────

def scan_tmp_suspicious() -> List[Finding]:
    """Check /tmp and /dev/shm for executables and suspicious files."""
    findings: List[Finding] = []
    suspicious_dirs = [Path("/tmp"), Path("/dev/shm"), Path("/var/tmp")]
    suspicious_names = re.compile(
        r"\.(sh|py|rb|pl|elf|out|bin|exe|so)$|^(\.|\-[a-z])", re.IGNORECASE
    )

    import re as _re
    sus_name_re = _re.compile(
        r"\.(sh|py|rb|pl|elf|out|bin|exe|so)$", _re.IGNORECASE
    )

    for tmp_dir in suspicious_dirs:
        if not tmp_dir.exists():
            continue
        try:
            for entry in tmp_dir.iterdir():
                try:
                    st = entry.lstat()
                    is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    is_suspicious_name = sus_name_re.search(entry.name)
                    is_hidden = entry.name.startswith(".")

                    if is_exec or (is_suspicious_name and st.st_size > 0) or (is_hidden and st.st_size > 1024):
                        findings.append(Finding(
                            module="filesystem_scan",
                            title=f"Suspicious file in {tmp_dir}: {entry.name}",
                            details=f"{entry} (size={st.st_size}B, exec={is_exec}, hidden={is_hidden})",
                            severity="HIGH" if is_exec else "MEDIUM",
                            recommendation=f"Investigate {entry}. Remove if unauthorized: rm -f '{entry}'",
                            evidence={"path": str(entry), "exec": is_exec,
                                      "hidden": is_hidden, "size": st.st_size},
                        ))
                except OSError:
                    continue
        except PermissionError:
            continue
    return findings


# ── 6. Sticky bit on directories ──────────────────────────────────────────────

def scan_missing_sticky_bit() -> List[Finding]:
    """Check shared dirs that SHOULD have sticky bit but don't."""
    findings: List[Finding] = []
    shared_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    for d in shared_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
            if not (mode & stat.S_ISVTX):
                findings.append(Finding(
                    module="filesystem_scan",
                    title=f"Missing sticky bit on {d}",
                    details=f"{d} is world-writable but has no sticky bit (mode={oct(mode & 0o777)})",
                    severity="HIGH",
                    recommendation=f"chmod +t {d}  — prevents users deleting each other's files",
                    evidence={"path": d, "mode": oct(mode & 0o777)},
                ))
        except OSError:
            continue
    return findings


def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [
        scan_misconfigured_permissions,
        scan_world_writable,
        scan_unexpected_suid,
        scan_tmp_suspicious,
        scan_missing_sticky_bit,
    ]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results

import re  # needed for scan_tmp_suspicious
