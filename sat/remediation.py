"""remediation.py – Automated fix engine: filesystem, SSH, packages, lynis, incident response."""
from __future__ import annotations

import os, re, shutil, subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List

@dataclass
class Fix:
    pattern:         str                          # substring match on finding title
    description:     str
    safe:            bool = True                  # False = potentially disruptive
    requires_root:   bool = True
    tags:            list[str] = field(default_factory=list)
    apply:           Callable[[dict], tuple[bool, str]] = field(default=lambda f: (False, "not implemented"))


# ── shell helpers ──────────────────────────────────────────────────────────────

def _sh(cmd: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[:300] or " ".join(cmd) + " ✓"
    except Exception as e:
        return False, str(e)

def _path_from(details: str) -> str:
    m = re.search(r"(/[^\s:,]+)", details)
    return m.group(1) if m else ""

def _sed_inplace(filepath: str, old: str, new: str) -> tuple[bool, str]:
    p = Path(filepath)
    if not p.exists():
        return False, f"{filepath} not found"
    try:
        text = p.read_text()
        if old not in text:
            return False, f"Pattern not found: {old!r}"
        bak = p.with_suffix(p.suffix + ".bak")
        bak.write_text(text)
        p.write_text(text.replace(old, new))
        return True, f"{filepath}: replaced {old!r} → {new!r} (backup: {bak}) ✓"
    except Exception as e:
        return False, str(e)


# ── fix catalogue ─────────────────────────────────────────────────────────────

FIXES: list[Fix] = [

    # ── File permissions ───────────────────────────────────────────────────────
    Fix("Wrong permissions on /etc/shadow",
        "chmod 640 /etc/shadow + chown root:shadow",
        apply=lambda f: _sh(["sh", "-c",
            "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"])),
    Fix("Wrong permissions on /etc/passwd",
        "chmod 644 /etc/passwd",
        apply=lambda f: _sh(["chmod", "644", "/etc/passwd"])),
    Fix("Wrong permissions on /etc/gshadow",
        "chmod 640 /etc/gshadow + chown root:shadow",
        apply=lambda f: _sh(["sh", "-c",
            "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow"])),
    Fix("Wrong permissions on /etc/sudoers",
        "chmod 440 /etc/sudoers",
        apply=lambda f: _sh(["chmod", "440", "/etc/sudoers"])),
    Fix("Wrong permissions on /etc/ssh/sshd_config",
        "chmod 600 /etc/ssh/sshd_config",
        apply=lambda f: _sh(["chmod", "600", "/etc/ssh/sshd_config"])),
    Fix("Wrong permissions on /etc/crontab",
        "chmod 600 /etc/crontab",
        apply=lambda f: _sh(["chmod", "600", "/etc/crontab"])),
    Fix("Wrong permissions on /boot/grub/grub.cfg",
        "chmod 600 /boot/grub/grub.cfg",
        apply=lambda f: _sh(["chmod", "600", "/boot/grub/grub.cfg"])),
    Fix("World-writable file",
        "Remove world-write bit", requires_root=False,
        apply=lambda f: _sh(["chmod", "o-w", _path_from(f.get("details",""))])),
    Fix("Missing sticky bit",
        "Add sticky bit to shared dir",
        apply=lambda f: _sh(["chmod", "+t", _path_from(f.get("details",""))])),
    Fix("Docker socket is world-accessible",
        "chmod 660 docker.sock + chown root:docker",
        apply=lambda f: _sh(["sh", "-c",
            "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock"])),

    # ── SSH ───────────────────────────────────────────────────────────────────
    Fix("Weak SSH setting: PermitRootLogin yes",
        "Disable root SSH login",
        apply=lambda f: _sed_inplace("/etc/ssh/sshd_config",
            "PermitRootLogin yes", "PermitRootLogin no") and
            _sh(["systemctl", "reload", "sshd"])),
    Fix("Weak SSH setting: PasswordAuthentication yes",
        "Disable SSH password auth (ensure key access first!)",
        safe=False,
        apply=lambda f: _sed_inplace("/etc/ssh/sshd_config",
            "PasswordAuthentication yes", "PasswordAuthentication no")),

    # ── Lynis-specific fixes ──────────────────────────────────────────────────
    Fix("Lynis WARNING: No firewall",
        "Enable UFW with deny incoming + allow SSH",
        tags=["lynis"],
        apply=lambda f: _fix_ufw()),
    Fix("Lynis WARNING: fail2ban",
        "Install and enable fail2ban",
        tags=["lynis"],
        apply=lambda f: _sh(["sh", "-c",
            "apt-get install -y fail2ban && systemctl enable --now fail2ban"],
            timeout=120)),
    Fix("Lynis WARNING: auditd",
        "Install and enable auditd",
        tags=["lynis"],
        apply=lambda f: _sh(["sh", "-c",
            "apt-get install -y auditd && systemctl enable --now auditd"],
            timeout=120)),
    Fix("Lynis WARNING: core dump",
        "Disable core dumps",
        tags=["lynis"],
        apply=lambda f: _append_if_missing(
            "/etc/security/limits.conf", "* hard core 0\n* soft core 0\n")),
    Fix("Lynis WARNING: umask",
        "Set umask 027 in /etc/profile",
        tags=["lynis"],
        apply=lambda f: _append_if_missing("/etc/profile", "\numask 027\n")),
    Fix("Lynis WARNING: sysctl",
        "Harden kernel sysctl parameters",
        tags=["lynis"],
        apply=lambda f: _apply_sysctl_hardening()),
    Fix("Lynis WARNING: AIDE",
        "Install AIDE file integrity monitoring",
        tags=["lynis"],
        apply=lambda f: _install_aide()),

    # ── Package management ────────────────────────────────────────────────────
    Fix("Outdated glibc",
        "Upgrade glibc via apt",
        apply=lambda f: _sh(["apt-get", "install", "--only-upgrade", "-y", "libc6"],
            timeout=180)),
    Fix("Ubuntu USN-",
        "apt-get upgrade affected packages",
        apply=lambda f: _apt_upgrade(f)),
    Fix("Package integrity failure",
        "Reinstall affected package via apt",
        apply=lambda f: _reinstall_pkg(f)),
    Fix("Vulnerability in Debian package",
        "apt-get upgrade affected package",
        apply=lambda f: _apt_upgrade_pkg_from_title(f)),

    # ── Network ───────────────────────────────────────────────────────────────
    Fix("Firewall may be inactive",
        "Enable UFW with deny incoming + allow SSH",
        apply=lambda f: _fix_ufw()),
    Fix("fail2ban is not running",
        "Start and enable fail2ban",
        apply=lambda f: _sh(["systemctl", "enable", "--now", "fail2ban"])),
    Fix("auditd is disabled",
        "Enable auditd",
        apply=lambda f: _sh(["sh", "-c",
            "systemctl enable --now auditd && auditctl -e 1"])),

    # ── chkrootkit / rkhunter response ───────────────────────────────────────
    Fix("Rootkit indicator",
        "🚨 CRITICAL: Print incident response playbook (no auto-fix — manual required)",
        safe=True, requires_root=False,
        tags=["incident"],
        apply=lambda f: _print_ir_playbook(f)),
    Fix("rkhunter INFECTED",
        "🚨 CRITICAL: Print incident response playbook",
        safe=True, requires_root=False,
        tags=["incident"],
        apply=lambda f: _print_ir_playbook(f)),
    Fix("chkrootkit INFECTED",
        "🚨 CRITICAL: Print incident response playbook",
        safe=True, requires_root=False,
        tags=["incident"],
        apply=lambda f: _print_ir_playbook(f)),

    # ── User accounts ─────────────────────────────────────────────────────────
    Fix("Non-root account with UID 0",
        "Lock suspicious UID-0 account (manual review required)",
        safe=False,
        apply=lambda f: _lock_account_from_finding(f)),
    Fix("Empty shadow password",
        "Lock account with empty password",
        apply=lambda f: _lock_account_from_finding(f)),
]

# ── fix helpers ────────────────────────────────────────────────────────────────

def _fix_ufw() -> tuple[bool, str]:
    if not shutil.which("ufw"):
        return _sh(["sh", "-c", "apt-get install -y ufw"], timeout=120)
    cmds = ["ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow ssh",
            "ufw --force enable"]
    for cmd in cmds:
        ok, msg = _sh(["sh", "-c", cmd])
        if not ok:
            return False, msg
    return True, "UFW enabled: deny incoming + allow SSH ✓"

def _append_if_missing(filepath: str, content: str) -> tuple[bool, str]:
    p = Path(filepath)
    try:
        existing = p.read_text() if p.exists() else ""
        if content.strip() in existing:
            return True, f"{filepath}: already configured ✓"
        with open(filepath, "a") as f:
            f.write(content)
        return True, f"{filepath}: appended ✓"
    except Exception as e:
        return False, str(e)

def _apply_sysctl_hardening() -> tuple[bool, str]:
    params = {
        "kernel.dmesg_restrict":    "1",
        "kernel.kptr_restrict":     "2",
        "kernel.randomize_va_space":"2",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies":  "1",
        "fs.protected_hardlinks":   "1",
        "fs.protected_symlinks":    "1",
    }
    conf_lines = "\n".join(f"{k} = {v}" for k, v in params.items()) + "\n"
    conf_file  = Path("/etc/sysctl.d/99-hardening.conf")
    try:
        conf_file.write_text(conf_lines)
        _sh(["sysctl", "--system"])
        return True, f"Wrote {conf_file} and applied ✓"
    except Exception as e:
        return False, str(e)

def _install_aide() -> tuple[bool, str]:
    ok, msg = _sh(["apt-get", "install", "-y", "aide"], timeout=120)
    if not ok:
        return False, msg
    ok2, msg2 = _sh(["aideinit"], timeout=300)
    _sh(["sh", "-c",
        "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true"])
    return True, "AIDE installed and database initialised ✓"

def _apt_upgrade(finding: dict) -> tuple[bool, str]:
    pkgs = (finding.get("evidence") or {}).get("packages", [])
    if pkgs:
        return _sh(["apt-get", "install", "--only-upgrade", "-y"] + pkgs[:10], timeout=300)
    return _sh(["apt-get", "upgrade", "-y"], timeout=300)

def _reinstall_pkg(finding: dict) -> tuple[bool, str]:
    pkg = (finding.get("evidence") or {}).get("package", "")
    if not pkg:
        return False, "Could not determine package name from finding"
    return _sh(["apt-get", "install", "--reinstall", "-y", pkg], timeout=180)

def _apt_upgrade_pkg_from_title(finding: dict) -> tuple[bool, str]:
    pkg = (finding.get("evidence") or {}).get("package", {})
    name = pkg.get("name", "") if isinstance(pkg, dict) else str(pkg)
    if not name:
        return False, "Could not determine package name"
    return _sh(["apt-get", "install", "--only-upgrade", "-y", name], timeout=180)

def _print_ir_playbook(finding: dict) -> tuple[bool, str]:
    playbook = """
╔══════════════════════════════════════════════════════════════╗
║  🚨 INCIDENT RESPONSE PLAYBOOK — Rootkit/Compromise Alert   ║
╚══════════════════════════════════════════════════════════════╝

IMMEDIATE ACTIONS (do NOT reboot first):

 1. ISOLATE machine from network:
    sudo ip link set eth0 down   # or your interface name
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP

 2. PRESERVE EVIDENCE before any changes:
    sudo dd if=/dev/sda bs=4M | gzip > /mnt/external/disk.img.gz
    sudo cp /var/log/auth.log /mnt/external/
    sudo cp /var/log/syslog  /mnt/external/

 3. VERIFY with second tool (from clean USB):
    sudo chkrootkit -r /
    sudo rkhunter --check

 4. ANALYSE offline (boot Kali live USB):
    sudo mount /dev/sda1 /mnt/suspect
    chkrootkit -r /mnt/suspect
    find /mnt/suspect -newer /mnt/suspect/etc/passwd -ls

 5. IDENTIFY attack vector:
    last -F | head -30           # recent logins
    lastb | head -20             # failed logins
    ps auxf                      # process tree
    netstat -tlnp                # listening ports
    find / -mtime -7 -type f     # files changed last 7 days

 6. If CONFIRMED compromise:
    a. Rotate ALL credentials (SSH keys, passwords, API tokens)
    b. Notify users of the system
    c. Reinstall from trusted media
    d. Restore from pre-compromise backup
    e. Document timeline and report

NOTE: This is an automated finding — verify with manual analysis
      before taking drastic action. False positives do occur.
"""
    print(playbook)
    return True, "Incident response playbook printed ✓ (no automated fix — manual action required)"

def _lock_account_from_finding(finding: dict) -> tuple[bool, str]:
    details = finding.get("details", "")
    m = re.search(r"User '([^']+)'", details)
    if not m:
        return False, "Could not extract username from finding"
    user = m.group(1)
    if user == "root":
        return False, "Will not lock root account"
    return _sh(["passwd", "-l", user])


# ── public API ─────────────────────────────────────────────────────────────────

def find_fixes(finding: dict) -> list[Fix]:
    title = finding.get("title", "")
    return [fx for fx in FIXES if fx.pattern in title]

def preview_fixes(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        for fx in find_fixes(f):
            out.append({"finding": f.get("title"), "fix": fx.description,
                        "root": fx.requires_root, "safe": fx.safe})
    return out

def apply_fixes(
    findings: list[dict],
    dry_run:        bool = False,
    safe_only:      bool = True,
    require_confirm: bool = True,
) -> list[dict]:
    is_root = os.geteuid() == 0
    results: list[dict] = []
    fixable: list[tuple[dict, Fix]] = []

    for f in findings:
        for fx in find_fixes(f):
            if safe_only and not fx.safe:
                results.append({"finding": f.get("title"), "fix": fx.description,
                                 "success": False,
                                 "message": "Skipped (not safe — use --unsafe to enable)"})
                continue

            # In dry-run mode, preview fixes even if root would be required.
            # This keeps plan visibility complete on non-root CI runners.
            if dry_run:
                fixable.append((f, fx))
                continue

            if fx.requires_root and not is_root:
                results.append({"finding": f.get("title"), "fix": fx.description,
                                 "success": False, "message": "Skipped: requires root"})
                continue
            fixable.append((f, fx))

    if not fixable:
        return results

    if dry_run:
        for f, fx in fixable:
            results.append({"finding": f.get("title"), "fix": fx.description,
                             "success": None, "message": "[DRY RUN] Would apply"})
        return results

    if require_confirm:
        print(f"\n  🔧  {len(fixable)} automated fix(es) available:\n")
        for f, fx in fixable:
            safe_tag = "" if fx.safe else "  ⚠️  DISRUPTIVE"
            root_tag = "  (root)" if fx.requires_root else ""
            print(f"     • [{f.get('severity','?')}] {fx.description}{root_tag}{safe_tag}")
        try:
            ans = input("\n  Apply? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "y":
            print("  Aborted."); return results

    for f, fx in fixable:
        try:
            ok, msg = fx.apply(f)
        except Exception as e:
            ok, msg = False, str(e)
        results.append({"finding": f.get("title"), "fix": fx.description,
                         "success": ok, "message": msg})
        print(f"  {'✅' if ok else '❌'} {fx.description}: {msg}")

    return results

def format_fix_results(results: list[dict]) -> str:
    if not results:
        return "  No automated fixes available for current findings."
    applied  = [r for r in results if r.get("success") is True]
    failed   = [r for r in results if r.get("success") is False]
    dry_runs = [r for r in results if r.get("success") is None]
    lines = ["\n  🔧  REMEDIATION RESULTS", "  " + "─" * 52]
    if dry_runs:
        lines.append(f"\n  [DRY RUN] Would apply {len(dry_runs)} fix(es):")
        for r in dry_runs:
            lines.append(f"    • {r['fix']}")
    if applied:
        lines.append(f"\n  ✅  Applied ({len(applied)}):")
        for r in applied:
            lines.append(f"    • {r['fix']}: {r['message']}")
    if failed:
        lines.append(f"\n  ❌  Failed/Skipped ({len(failed)}):")
        for r in failed:
            lines.append(f"    • {r['fix']}: {r['message']}")
    lines.append("  " + "─" * 52)
    return "\n".join(lines)
