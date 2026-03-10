"""
alert.py – Alert mode: run scan + notify ONLY when new CRITICAL/HIGH findings appear.

Standalone script, also importable as a module.

Usage:
    python3 alert.py                             # scan + alert if new HIGH/CRITICAL
    python3 alert.py --telegram                  # send Telegram alert
    python3 alert.py --email you@host.com        # send email alert
    python3 alert.py --min-severity CRITICAL     # only on new CRITICAL
    python3 alert.py --dry-run                   # scan + print without sending
    python3 alert.py --channels telegram email   # multi-channel
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import List, Optional

WORKDIR = Path(__file__).resolve().parent

# ── severity helpers ──────────────────────────────────────────────────────────

SEV_ORDER  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEV_EMOJI  = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "💀"}


def _sev_gte(sev: str, min_sev: str) -> bool:
    return SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(min_sev, 0)


# ── report loading ────────────────────────────────────────────────────────────

def _load_latest_report() -> Optional[dict]:
    p = WORKDIR / "reports" / "latest_report.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


# ── scan runner ───────────────────────────────────────────────────────────────

def run_scan(deep: bool = False, baseline_label: str = "default") -> tuple[Optional[dict], Optional[dict]]:
    """Run a scan and return (report, diff) or (None, None) on failure."""
    cmd = [sys.executable, str(WORKDIR / "main.py"),
           "scan", "--no-dashboard", "--save-baseline",
           f"--baseline={baseline_label}"]
    if deep:
        cmd.append("--deep")
    try:
        r = subprocess.run(cmd, cwd=str(WORKDIR), capture_output=True,
                           text=True, timeout=600)
        if r.returncode not in (0, 1):
            print(f"[alert] Scan failed (rc={r.returncode}): {r.stderr[:200]}", file=sys.stderr)
            return None, None
    except subprocess.TimeoutExpired:
        print("[alert] Scan timed out", file=sys.stderr)
        return None, None
    except Exception as e:
        print(f"[alert] Scan error: {e}", file=sys.stderr)
        return None, None

    report = _load_latest_report()
    return report, None


# ── diff analysis ─────────────────────────────────────────────────────────────

@dataclass
class AlertSummary:
    new_critical:  List[dict] = field(default_factory=list)
    new_high:      List[dict] = field(default_factory=list)
    new_medium:    List[dict] = field(default_factory=list)
    new_low:       List[dict] = field(default_factory=list)
    resolved:      List[dict] = field(default_factory=list)
    posture:       str = "UNKNOWN"
    risk_score:    int = 0
    scanned_at:    str = ""

    @property
    def total_new(self) -> int:
        return len(self.new_critical) + len(self.new_high) + len(self.new_medium) + len(self.new_low)

    @property
    def has_critical_or_high(self) -> bool:
        return len(self.new_critical) + len(self.new_high) > 0

    def new_above(self, min_sev: str) -> List[dict]:
        out = []
        for bucket in (self.new_critical, self.new_high, self.new_medium, self.new_low):
            for f in bucket:
                if _sev_gte(f.get("severity","LOW"), min_sev):
                    out.append(f)
        return out


def build_alert_summary(report: dict, baseline_label: str = "default") -> AlertSummary:
    """Compare current report findings against saved baseline."""
    sys.path.insert(0, str(WORKDIR))
    from scanner.baseline import load_baseline, diff_findings

    findings   = report.get("findings", [])
    analysis   = report.get("analysis", {})
    summary    = AlertSummary(
        posture    = analysis.get("posture", "UNKNOWN"),
        risk_score = analysis.get("risk_score", 0),
        scanned_at = report.get("scanned_at", ""),
    )

    baseline = load_baseline(baseline_label)
    if baseline is None:
        # First run – treat all HIGH/CRITICAL as new
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev == "CRITICAL":   summary.new_critical.append(f)
            elif sev == "HIGH":     summary.new_high.append(f)
            elif sev == "MEDIUM":   summary.new_medium.append(f)
            else:                   summary.new_low.append(f)
        return summary

    diff = diff_findings(findings, baseline)
    for f in diff.get("new", []):
        sev = f.get("severity", "LOW")
        if sev == "CRITICAL":   summary.new_critical.append(f)
        elif sev == "HIGH":     summary.new_high.append(f)
        elif sev == "MEDIUM":   summary.new_medium.append(f)
        else:                   summary.new_low.append(f)
    summary.resolved = diff.get("resolved", [])
    return summary


# ── message formatters ────────────────────────────────────────────────────────

def _format_telegram(s: AlertSummary, min_sev: str = "HIGH") -> str:
    emoji = SEV_EMOJI.get(s.posture.split()[0] if s.posture else "LOW", "⚪")
    lines = [
        f"🚨 *Security Alert – New Findings*",
        f"Posture: *{emoji} {s.posture}* | Score: `{s.risk_score}`",
        f"Scanned: {s.scanned_at[:16].replace('T',' ')} UTC",
        "",
        f"💀 New CRITICAL: {len(s.new_critical)} | 🔴 New HIGH: {len(s.new_high)}",
    ]
    if s.new_medium:
        lines.append(f"🟠 New MEDIUM: {len(s.new_medium)}")
    if s.resolved:
        lines.append(f"✅ Resolved: {len(s.resolved)}")
    lines.append("")
    lines.append("*Findings requiring action:*")
    for f in s.new_above(min_sev)[:8]:
        sev  = f.get("severity","?")
        icon = SEV_EMOJI.get(sev, "•")
        lines.append(f"{icon} [{sev}] {f.get('title','')[:70]}")
    if s.total_new > 8:
        lines.append(f"… and {s.total_new - 8} more new findings")
    return "\n".join(lines)


def _format_text(s: AlertSummary, min_sev: str = "HIGH") -> str:
    lines = [
        "=" * 58,
        "  🚨  SECURITY ALERT — NEW FINDINGS DETECTED",
        "=" * 58,
        f"  Posture    : {s.posture}",
        f"  Risk Score : {s.risk_score}",
        f"  Scanned    : {s.scanned_at[:19].replace('T',' ')} UTC",
        "",
        f"  NEW CRITICAL : {len(s.new_critical)}",
        f"  NEW HIGH     : {len(s.new_high)}",
        f"  NEW MEDIUM   : {len(s.new_medium)}",
        f"  NEW LOW      : {len(s.new_low)}",
        f"  RESOLVED     : {len(s.resolved)}",
        "",
        "  Findings requiring action:",
    ]
    for f in s.new_above(min_sev)[:10]:
        sev = f.get("severity","?")
        lines.append(f"    [{sev:<8}] {f.get('title','')[:70]}")
        if f.get("details"):
            lines.append(f"               {f['details'][:80]}")
    lines.append("=" * 58)
    return "\n".join(lines)


def _format_email_html(s: AlertSummary, min_sev: str = "HIGH") -> str:
    SEV_COLOR = {"CRITICAL":"#ff2244","HIGH":"#ff6600","MEDIUM":"#ffaa00","LOW":"#888888"}
    rows = ""
    for f in s.new_above(min_sev)[:15]:
        sev = f.get("severity","LOW")
        c   = SEV_COLOR.get(sev,"#888")
        rows += (f"<tr><td style='padding:6px 10px'>"
                 f"<span style='background:{c};color:#000;padding:2px 6px;"
                 f"border-radius:3px;font-size:11px;font-weight:bold'>{sev}</span>"
                 f"</td><td style='padding:6px 10px;font-family:monospace;font-size:13px'>"
                 f"{f.get('title','')[:80]}</td><td style='padding:6px;color:#666;"
                 f"font-size:12px'>{f.get('details','')[:80]}</td></tr>")
    return f"""<html><body style='font-family:Arial,sans-serif;background:#0a0a0a;color:#eee;padding:20px'>
<h2 style='color:#ff4444'>🚨 Security Alert – New Findings Detected</h2>
<table style='border-collapse:collapse;margin-bottom:12px'>
  <tr><td><b>Posture:</b></td><td style='color:#ff8800'>{s.posture}</td></tr>
  <tr><td><b>Risk Score:</b></td><td>{s.risk_score}</td></tr>
  <tr><td><b>Scanned:</b></td><td>{s.scanned_at[:19].replace('T',' ')} UTC</td></tr>
  <tr><td><b>New CRITICAL:</b></td><td style='color:#ff2244'>{len(s.new_critical)}</td></tr>
  <tr><td><b>New HIGH:</b></td><td style='color:#ff6600'>{len(s.new_high)}</td></tr>
  <tr><td><b>Resolved:</b></td><td style='color:#00cc66'>{len(s.resolved)}</td></tr>
</table>
<h3 style='color:#ffaa00'>Findings Requiring Action ({min_sev}+):</h3>
<table style='width:100%;border-collapse:collapse;background:#111'><tr style='background:#222'>
  <th style='padding:8px;text-align:left'>Severity</th>
  <th style='padding:8px;text-align:left'>Finding</th>
  <th style='padding:8px;text-align:left'>Details</th>
</tr>{rows}</table>
<p style='color:#555;font-size:12px;margin-top:16px'>
  Security Audit Tool – Local machine scan. Authorized use only.
</p></body></html>"""


# ── notification channels ─────────────────────────────────────────────────────

def send_telegram(summary: AlertSummary, token: str, chat_id: str,
                  min_sev: str = "HIGH") -> bool:
    """Send Telegram message via Bot API."""
    try:
        from urllib.request import urlopen, Request as UReq
        msg  = _format_telegram(summary, min_sev)
        body = json.dumps({
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "Markdown",
        }).encode()
        req = UReq(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
            return resp.get("ok", False)
    except Exception as e:
        print(f"[alert] Telegram error: {e}", file=sys.stderr)
        return False


def send_email(summary: AlertSummary, to_addr: str, min_sev: str = "HIGH",
               smtp_host: str = "localhost", smtp_port: int = 25,
               smtp_user: str = "", smtp_pass: str = "",
               from_addr: str = "security-audit@localhost") -> bool:
    """Send email alert via SMTP."""
    try:
        html_body = _format_email_html(summary, min_sev)
        msg = MIMEText(html_body, "html")
        msg["Subject"] = (
            f"[Security Alert] {len(summary.new_critical)} CRITICAL, "
            f"{len(summary.new_high)} HIGH new findings – {summary.posture}"
        )
        msg["From"] = from_addr
        msg["To"]   = to_addr

        use_tls = smtp_port in (465, 587) or bool(smtp_pass)
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port) as s:
                s.ehlo()
                s.starttls()
                if smtp_user:
                    s.login(smtp_user, smtp_pass)
                s.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as s:
                s.send_message(msg)
        return True
    except Exception as e:
        print(f"[alert] Email error: {e}", file=sys.stderr)
        return False


def send_webhook(summary: AlertSummary, url: str, min_sev: str = "HIGH") -> bool:
    """POST JSON payload to a webhook URL (Slack, Teams, custom)."""
    try:
        from urllib.request import urlopen, Request as UReq
        payload = {
            "text": _format_text(summary, min_sev),
            "posture":      summary.posture,
            "risk_score":   summary.risk_score,
            "new_critical": len(summary.new_critical),
            "new_high":     len(summary.new_high),
            "new_medium":   len(summary.new_medium),
            "resolved":     len(summary.resolved),
            "scanned_at":   summary.scanned_at,
            "findings":     [
                {"severity": f.get("severity"), "title": f.get("title"),
                 "module": f.get("module"), "details": f.get("details","")}
                for f in summary.new_above(min_sev)[:20]
            ],
        }
        body = json.dumps(payload).encode()
        req  = UReq(url, data=body, method="POST",
                    headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10):
            return True
    except Exception as e:
        print(f"[alert] Webhook error: {e}", file=sys.stderr)
        return False


# ── main runner ───────────────────────────────────────────────────────────────

def run_alert(
    min_severity:   str  = "HIGH",
    baseline_label: str  = "default",
    deep:           bool = False,
    dry_run:        bool = False,
    telegram_token: str  = "",
    telegram_chat:  str  = "",
    email_to:       str  = "",
    webhook_url:    str  = "",
    smtp_host:      str  = "localhost",
    smtp_port:      int  = 25,
    smtp_user:      str  = "",
    smtp_pass:      str  = "",
    always_notify:  bool = False,
) -> int:
    """
    Run scan → build diff summary → notify if new findings above threshold.

    Returns:
        0 – no alert needed (or dry-run)
        1 – alert sent
        2 – scan failed
    """
    print(f"[alert] Running scan (deep={deep}, baseline={baseline_label})…")
    report, _ = run_scan(deep=deep, baseline_label=baseline_label)
    if report is None:
        print("[alert] Scan did not produce a report.", file=sys.stderr)
        return 2

    summary = build_alert_summary(report, baseline_label)

    alert_needed = always_notify or summary.total_new > 0 and (
        len(summary.new_above(min_severity)) > 0
    )

    if not alert_needed:
        print(
            f"[alert] No new {min_severity}+ findings "
            f"({summary.total_new} total new, {len(summary.resolved)} resolved). "
            "No alert sent."
        )
        return 0

    # Always print to stdout/log
    print(_format_text(summary, min_severity))

    if dry_run:
        print("\n[alert] --dry-run: channels not triggered.")
        return 1

    sent = []
    if telegram_token and telegram_chat:
        ok = send_telegram(summary, telegram_token, telegram_chat, min_severity)
        sent.append(f"telegram({'✅' if ok else '❌'})")

    if email_to:
        ok = send_email(summary, email_to, min_severity,
                        smtp_host, smtp_port, smtp_user, smtp_pass)
        sent.append(f"email({'✅' if ok else '❌'})")

    if webhook_url:
        ok = send_webhook(summary, webhook_url, min_severity)
        sent.append(f"webhook({'✅' if ok else '❌'})")

    if not sent:
        print("[alert] No channels configured. Set TELEGRAM_TOKEN, EMAIL_TO, or WEBHOOK_URL.")

    print(f"[alert] Notifications: {', '.join(sent) if sent else 'none'}")
    return 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="🔔 Security Audit – Alert Mode (notify on new CRITICAL/HIGH only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 alert.py                                    # scan, print if new HIGH/CRITICAL
  python3 alert.py --min-severity CRITICAL            # only critical findings
  python3 alert.py --dry-run                          # scan + print, no notifications
  python3 alert.py --telegram                         # use TELEGRAM_TOKEN + TELEGRAM_CHAT_ID env vars
  python3 alert.py --email you@company.com            # email via SMTP_HOST env var
  python3 alert.py --webhook https://hooks.slack.com/… # Slack / Teams / custom
  python3 alert.py --always-notify                    # notify even if no new findings
  python3 alert.py --deep --telegram                  # deep scan + Telegram
        """,
    )
    p.add_argument("--min-severity", choices=["LOW","MEDIUM","HIGH","CRITICAL"],
                   default="HIGH", help="Minimum severity to trigger alert (default: HIGH)")
    p.add_argument("--baseline", default="default", metavar="LABEL",
                   help="Baseline label to compare against (default: 'default')")
    p.add_argument("--deep", action="store_true",
                   help="Enable deep scan (nmap vuln, rkhunter, aide…)")
    p.add_argument("--dry-run", action="store_true",
                   help="Scan and print alert but do NOT send notifications")
    p.add_argument("--always-notify", action="store_true",
                   help="Send notification even if no new findings")

    # Channels
    ch = p.add_argument_group("notification channels")
    ch.add_argument("--telegram", action="store_true",
                    help="Send Telegram alert (reads TELEGRAM_TOKEN + TELEGRAM_CHAT_ID from env)")
    ch.add_argument("--telegram-token", default="",
                    help="Telegram Bot token (overrides env var)")
    ch.add_argument("--telegram-chat-id", default="",
                    help="Telegram chat ID (overrides env var)")
    ch.add_argument("--email", metavar="TO_ADDRESS",
                    help="Send email alert to this address")
    ch.add_argument("--webhook", metavar="URL",
                    help="POST JSON alert to webhook URL (Slack, Teams, custom)")
    ch.add_argument("--smtp-host", default=os.environ.get("SMTP_HOST","localhost"))
    ch.add_argument("--smtp-port", type=int, default=int(os.environ.get("SMTP_PORT","25")))
    ch.add_argument("--smtp-user", default=os.environ.get("SMTP_USER",""))
    ch.add_argument("--smtp-pass", default=os.environ.get("SMTP_PASS",""))
    return p


def main() -> None:
    args = _build_parser().parse_args()

    tg_token = args.telegram_token or os.environ.get("TELEGRAM_TOKEN","")
    tg_chat  = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID","")

    if args.telegram and not tg_token:
        print("[alert] --telegram requires TELEGRAM_TOKEN env var or --telegram-token",
              file=sys.stderr)
        sys.exit(2)

    rc = run_alert(
        min_severity   = args.min_severity,
        baseline_label = args.baseline,
        deep           = args.deep,
        dry_run        = args.dry_run,
        telegram_token = tg_token   if args.telegram else "",
        telegram_chat  = tg_chat    if args.telegram else "",
        email_to       = args.email or "",
        webhook_url    = args.webhook or "",
        smtp_host      = args.smtp_host,
        smtp_port      = args.smtp_port,
        smtp_user      = args.smtp_user,
        smtp_pass      = args.smtp_pass,
        always_notify  = args.always_notify,
    )
    sys.exit(rc if rc == 2 else 0)


if __name__ == "__main__":
    main()
