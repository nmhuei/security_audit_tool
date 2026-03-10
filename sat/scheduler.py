"""
scheduler.py – Generate and install systemd timers or cron jobs for periodic scanning.
Also provides alert-on-drift mode: only notifies when new CRITICAL/HIGH findings appear.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Literal


TOOL_DIR = Path(__file__).resolve().parent


# ── systemd timer ─────────────────────────────────────────────────────────────

SERVICE_TEMPLATE = """\
[Unit]
Description=Security Audit Tool – local scan
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory={workdir}
ExecStart={python} {main} scan --no-dashboard --save-baseline {extra_args}
StandardOutput=append:/var/log/security-audit.log
StandardError=append:/var/log/security-audit.log
"""

TIMER_TEMPLATE = """\
[Unit]
Description=Security Audit Tool – periodic scan timer

[Timer]
OnCalendar={schedule}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""

ALERT_SERVICE_TEMPLATE = """\
[Unit]
Description=Security Audit Tool – drift alert service
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory={workdir}
ExecStart={python} {alert_script}
StandardOutput=append:/var/log/security-audit-alert.log
StandardError=append:/var/log/security-audit-alert.log
"""

# ── cron ──────────────────────────────────────────────────────────────────────

CRON_SCHEDULE_MAP = {
    "daily":   "0 3 * * *",
    "weekly":  "0 3 * * 0",
    "hourly":  "0 * * * *",
    "monthly": "0 3 1 * *",
}

SYSTEMD_SCHEDULE_MAP = {
    "daily":   "daily",
    "weekly":  "weekly",
    "hourly":  "hourly",
    "monthly": "monthly",
}


# ── alert script generator ────────────────────────────────────────────────────

ALERT_SCRIPT = '''\
#!/usr/bin/env python3
"""Auto-generated alert script: run scan, notify only on new CRITICAL/HIGH findings."""
import json, os, subprocess, sys
from pathlib import Path

WORKDIR = {workdir!r}
PYTHON  = {python!r}
MAIN    = {main!r}
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

def run_scan():
    r = subprocess.run(
        [PYTHON, MAIN, "scan", "--no-dashboard", "--save-baseline"],
        cwd=WORKDIR, capture_output=True, text=True, timeout=600,
    )
    return r.returncode

def load_report():
    p = Path(WORKDIR) / "reports" / "latest_report.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())

def send_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    import urllib.request, urllib.parse
    data = urllib.parse.urlencode({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "Markdown",
    }).encode()
    try:
        urllib.request.urlopen(
            f"https://api.telegram.org/bot{{TELEGRAM_TOKEN}}/sendMessage",
            data=data, timeout=15,
        )
    except Exception as e:
        print(f"Telegram send failed: {{e}}", file=sys.stderr)

def main():
    print("Running security audit scan...")
    run_scan()
    report = load_report()
    if not report:
        return

    drift = report.get("analysis", {}).get("drift", {})
    new_crit = drift.get("new_critical", 0)
    new_high = drift.get("new_high", 0)
    new_count = drift.get("new_count", 0)
    new_findings = drift.get("new_findings", [])

    if new_crit == 0 and new_high == 0:
        print(f"No new CRITICAL/HIGH findings ({{new_count}} new LOW/MEDIUM). No alert sent.")
        return

    # Build alert message
    posture = report.get("analysis", {}).get("posture", "?")
    score   = report.get("analysis", {}).get("risk_score", 0)
    lines   = [
        f"🚨 *Security Alert – New Findings Detected*",
        f"Posture: *{{posture}}* | Risk Score: `{{score}}`",
        f"💀 New CRITICAL: {{new_crit}} | 🔴 New HIGH: {{new_high}}",
        "",
        "*New Critical/High Findings:*",
    ]
    for f in new_findings:
        sev = f.get("severity","?")
        if sev in ("CRITICAL", "HIGH"):
            lines.append(f"• [{{sev}}] {{f.get('title','')[:80]}}")

    msg = "\\n".join(lines)
    print(msg)
    send_telegram(msg)

if __name__ == "__main__":
    main()
'''


# ── public install functions ───────────────────────────────────────────────────

def install_systemd_timer(
    schedule: Literal["daily", "weekly", "hourly", "monthly"] = "daily",
    deep: bool = False,
    alert_only: bool = False,
    telegram_token: str = "",
    telegram_chat_id: str = "",
) -> tuple[bool, str]:
    """Install systemd timer + service for periodic scanning."""
    if os.geteuid() != 0:
        return False, "Requires root (sudo python3 main.py schedule --install)"

    python_bin = _find_python()
    main_py    = str(TOOL_DIR / "main.py")
    workdir    = str(TOOL_DIR)
    on_cal     = SYSTEMD_SCHEDULE_MAP.get(schedule, "daily")
    extra_args = "--deep" if deep else ""

    # Write alert script
    alert_script_path = TOOL_DIR / "alert_scan.py"
    alert_script_path.write_text(
        ALERT_SCRIPT.format(
            workdir=workdir, python=python_bin, main=main_py,
        )
    )
    alert_script_path.chmod(0o755)

    service_name = "security-audit"
    service_content = SERVICE_TEMPLATE.format(
        workdir=workdir, python=python_bin, main=main_py,
        extra_args=extra_args,
    )
    timer_content = TIMER_TEMPLATE.format(schedule=on_cal)

    # Write alert service (separate unit)
    alert_svc_content = ALERT_SERVICE_TEMPLATE.format(
        workdir=workdir, python=python_bin,
        alert_script=str(alert_script_path),
    )

    svc_path   = Path(f"/etc/systemd/system/{service_name}.service")
    timer_path = Path(f"/etc/systemd/system/{service_name}.timer")
    alert_path = Path(f"/etc/systemd/system/{service_name}-alert.service")
    alert_timer= Path(f"/etc/systemd/system/{service_name}-alert.timer")

    try:
        svc_path.write_text(service_content)
        timer_path.write_text(timer_content)

        if alert_only or telegram_token:
            # Write env file for telegram credentials
            env_file = Path(f"/etc/systemd/system/{service_name}-alert.env")
            env_file.write_text(
                f"TELEGRAM_TOKEN={telegram_token}\n"
                f"TELEGRAM_CHAT_ID={telegram_chat_id}\n"
            )
            env_file.chmod(0o600)

            alert_svc_with_env = alert_svc_content + f"EnvironmentFile={env_file}\n"
            alert_path.write_text(alert_svc_with_env)
            alert_timer.write_text(timer_content.replace(
                on_cal, f"{on_cal}\nOnCalendar={on_cal}"
            ))

        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", f"{service_name}.timer"], check=True)

        if alert_only or telegram_token:
            subprocess.run(["systemctl", "enable", "--now",
                           f"{service_name}-alert.timer"], check=True)

        return True, (
            f"✅ Installed systemd timer: {service_name}.timer ({schedule})\n"
            f"   Service file: {svc_path}\n"
            f"   Timer file:   {timer_path}\n"
            f"   Logs: journalctl -u {service_name}.service -f\n"
            f"   Next run: systemctl list-timers {service_name}.timer"
        )
    except Exception as e:
        return False, f"Failed to install systemd timer: {e}"


def install_cron(
    schedule: Literal["daily", "weekly", "hourly", "monthly"] = "daily",
    deep: bool = False,
    user: str = "root",
) -> tuple[bool, str]:
    """Install cron job (fallback for non-systemd systems)."""
    python_bin  = _find_python()
    main_py     = str(TOOL_DIR / "main.py")
    workdir     = str(TOOL_DIR)
    cron_expr   = CRON_SCHEDULE_MAP.get(schedule, "0 3 * * *")
    extra_args  = "--deep" if deep else ""

    cron_line = (
        f"{cron_expr}  cd {workdir} && {python_bin} {main_py} "
        f"scan --no-dashboard --save-baseline {extra_args} "
        f">> /var/log/security-audit.log 2>&1"
    )
    cron_file = Path(f"/etc/cron.d/security-audit")
    try:
        cron_file.write_text(f"# Security Audit Tool – auto-generated\n{cron_line}\n")
        cron_file.chmod(0o644)
        return True, (
            f"✅ Installed cron job: {cron_file}\n"
            f"   Schedule: {cron_expr} ({schedule})\n"
            f"   Logs: /var/log/security-audit.log"
        )
    except Exception as e:
        return False, f"Failed to install cron job: {e}"


def remove_schedule() -> tuple[bool, str]:
    """Remove installed systemd timers and cron jobs."""
    msgs = []
    for unit in ["security-audit.timer", "security-audit.service",
                 "security-audit-alert.timer", "security-audit-alert.service"]:
        subprocess.run(["systemctl", "disable", "--now", unit],
                       capture_output=True)
        p = Path(f"/etc/systemd/system/{unit}")
        if p.exists():
            p.unlink()
            msgs.append(f"Removed {p}")

    cron = Path("/etc/cron.d/security-audit")
    if cron.exists():
        cron.unlink()
        msgs.append(f"Removed {cron}")

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    return True, "\n".join(msgs) if msgs else "Nothing to remove"


def show_schedule_status() -> str:
    """Show current timer/cron status."""
    lines = ["\n  Scheduling Status\n  " + "─" * 40]

    # systemd
    for timer in ["security-audit.timer", "security-audit-alert.timer"]:
        r = subprocess.run(
            ["systemctl", "is-active", timer],
            capture_output=True, text=True
        )
        status = r.stdout.strip()
        icon = "✅" if status == "active" else "❌"
        lines.append(f"  {icon} systemd: {timer} [{status}]")

    # cron
    cron = Path("/etc/cron.d/security-audit")
    lines.append(f"  {'✅' if cron.exists() else '❌'} cron: {cron}")

    # Next run
    r = subprocess.run(
        ["systemctl", "list-timers", "security-audit.timer", "--no-pager"],
        capture_output=True, text=True
    )
    if r.stdout.strip():
        lines.append("\n  Next scheduled run:")
        for line in r.stdout.splitlines()[1:3]:
            lines.append(f"    {line.strip()}")

    lines.append("  " + "─" * 40)
    return "\n".join(lines)


def _find_python() -> str:
    """Find the Python interpreter running this script."""
    import sys
    return sys.executable or "python3"
