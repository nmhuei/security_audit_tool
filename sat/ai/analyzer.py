"""analyzer.py – Risk analysis + rich system context for AI insights."""
from __future__ import annotations
import json
import os
import platform
import subprocess
from collections import Counter
from typing import Dict, List, Optional
from .providers import call_with_fallback

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_SCORE  = {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}
POSTURE_EMOJI   = {"SECURE": "🟢", "LOW RISK": "🟡", "MEDIUM RISK": "🟠", "HIGH RISK": "🔴", "CRITICAL": "💀"}


def prioritize_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_SCORE.get(f.get("severity", "LOW"), 1), reverse=True)

def classify_posture(findings):
    if not findings: return "SECURE"
    score = sum(SEVERITY_SCORE.get(f.get("severity", "LOW"), 1) for f in findings)
    if score >= 80: return "CRITICAL"
    if score >= 40: return "HIGH RISK"
    if score >= 20: return "MEDIUM RISK"
    if score >= 5:  return "LOW RISK"
    return "SECURE"

def risk_score(findings):
    return sum(SEVERITY_SCORE.get(f.get("severity", "LOW"), 1) for f in findings)

def recommendations(findings):
    seen, recs = set(), []
    for f in prioritize_findings(findings):
        rec = f.get("recommendation")
        if rec and rec not in seen:
            seen.add(rec); recs.append(rec)
    return recs[:15]

def group_by_module(findings):
    groups = {}
    for f in findings:
        groups.setdefault(f.get("module", "unknown"), []).append(f)
    return groups

def analyze(findings: List[dict]) -> Dict:
    ordered = prioritize_findings(findings)
    counts  = Counter(f.get("severity", "LOW") for f in findings)
    return {
        "total_findings":  len(findings),
        "risk_score":      risk_score(findings),
        "severity_counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "posture":         classify_posture(findings),
        "top_findings":    ordered[:10],
        "recommendations": recommendations(ordered),
        "by_module":       {mod: len(items) for mod, items in group_by_module(findings).items()},
    }


# ── System context collector ───────────────────────────────────────────────────

def _collect_system_context() -> dict:
    """Gather real system info to enrich AI prompt."""
    ctx = {}

    # OS & kernel
    ctx["kernel"]  = platform.release()
    ctx["machine"] = platform.machine()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                k, _, v = line.partition("=")
                if k in ("NAME", "VERSION_ID", "ID"):
                    ctx[k.lower()] = v.strip().strip('"')
    except Exception:
        pass

    # Uptime
    try:
        with open("/proc/uptime") as f:
            seconds = float(f.read().split()[0])
            ctx["uptime_days"] = round(seconds / 86400, 1)
    except Exception:
        pass

    # Users with login shells
    try:
        with open("/etc/passwd") as f:
            login_users = [
                line.split(":")[0] for line in f
                if line.split(":")[6].strip() not in
                   {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""}
                and not line.startswith("#")
                and len(line.split(":")) >= 7
            ]
        ctx["login_users"] = login_users[:20]
    except Exception:
        pass

    # Listening services
    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        listeners = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                listeners.append(parts[3])  # local address:port
        ctx["listening_ports"] = listeners[:30]
    except Exception:
        pass

    # Running services (systemd)
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-pager", "--no-legend"],
            text=True, timeout=10, stderr=subprocess.DEVNULL
        )
        services = [line.split()[0] for line in out.strip().splitlines() if line.strip()]
        ctx["running_services"] = services[:30]
    except Exception:
        pass

    # Docker containers
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}:{{.Image}}"],
            text=True, timeout=10, stderr=subprocess.DEVNULL
        )
        ctx["docker_containers"] = out.strip().splitlines()[:10]
    except Exception:
        pass

    # sudo users
    try:
        out = subprocess.check_output(
            ["getent", "group", "sudo"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        members = out.strip().split(":")[-1].split(",")
        ctx["sudo_users"] = [m for m in members if m.strip()]
    except Exception:
        pass

    # Last logins
    try:
        out = subprocess.check_output(
            ["last", "-n", "5", "-F"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        ctx["recent_logins"] = out.strip().splitlines()[:5]
    except Exception:
        pass

    # Firewall state
    try:
        out = subprocess.check_output(
            ["ufw", "status"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        ctx["firewall"] = out.splitlines()[0].strip() if out else "unknown"
    except Exception:
        ctx["firewall"] = "unknown"

    return ctx


def _build_ai_prompt(findings: List[dict], ctx: dict) -> str:
    """Build rich, context-aware prompt for the LLM."""
    all_findings = prioritize_findings(findings)   # send ALL, sorted

    # Group by severity
    by_sev: dict[str, list] = {}
    for f in all_findings:
        by_sev.setdefault(f.get("severity", "LOW"), []).append(f)

    findings_text = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = by_sev.get(sev, [])
        if not group:
            continue
        findings_text += f"\n### {sev} ({len(group)} findings)\n"
        for f in group[:10]:   # up to 10 per severity level
            findings_text += f"- [{f.get('module','')}] {f.get('title','')}: {f.get('details','')[:150]}\n"
        if len(group) > 10:
            findings_text += f"  ... and {len(group)-10} more {sev} findings\n"

    # System context block
    ctx_lines = []
    if ctx.get("name"):        ctx_lines.append(f"OS: {ctx['name']} {ctx.get('version_id','')}")
    if ctx.get("kernel"):      ctx_lines.append(f"Kernel: {ctx['kernel']} ({ctx.get('machine','')})")
    if ctx.get("uptime_days"): ctx_lines.append(f"Uptime: {ctx['uptime_days']} days")
    if ctx.get("login_users"): ctx_lines.append(f"Login users: {', '.join(ctx['login_users'])}")
    if ctx.get("sudo_users"):  ctx_lines.append(f"Sudo users: {', '.join(ctx['sudo_users'])}")
    if ctx.get("firewall"):    ctx_lines.append(f"Firewall: {ctx['firewall']}")
    if ctx.get("listening_ports"):
        ctx_lines.append(f"Listening ports: {', '.join(ctx['listening_ports'][:10])}")
    if ctx.get("running_services"):
        ctx_lines.append(f"Running services: {', '.join(ctx['running_services'][:10])}")
    if ctx.get("docker_containers"):
        ctx_lines.append(f"Docker containers: {', '.join(ctx['docker_containers'])}")
    if ctx.get("recent_logins"):
        ctx_lines.append("Recent logins:\n  " + "\n  ".join(ctx["recent_logins"]))

    ctx_text = "\n".join(ctx_lines)

    total = len(findings)
    crit  = len(by_sev.get("CRITICAL", []))
    high  = len(by_sev.get("HIGH", []))

    return f"""You are a senior penetration tester and Linux sysadmin reviewing a local machine security audit.

## System Context
{ctx_text}

## Scan Results ({total} total findings, {crit} CRITICAL, {high} HIGH)
{findings_text}

Provide a concise, actionable security assessment in exactly 4 sections:

1. **Risk Summary** (3 sentences max): Overall security posture given this specific system, kernel version, and services.

2. **Most Dangerous Attack Chains** (bullet list, max 5): Which specific findings can be COMBINED for privilege escalation or lateral movement. Be concrete — name the CVEs/findings.

3. **Priority Actions** (numbered, max 6): Specific shell commands or steps to fix the highest-impact issues first. Include actual commands where possible.

4. **Positive Notes** (1-2 sentences): What is already configured well.

Be direct, technical, and specific to this machine's configuration. No generic advice."""


def ai_analyze(
    findings: List[dict],
    provider: Optional[str] = None,
    **_,
) -> tuple[Optional[str], Optional[str]]:
    """
    Analyze findings with full system context via LLM.
    Returns: (text, provider_used)
    """
    if not findings:
        return None, None

    ctx = _collect_system_context()
    prompt = _build_ai_prompt(findings, ctx)
    return call_with_fallback(prompt, max_tokens=800, provider=provider)


# ── Output formatters ──────────────────────────────────────────────────────────

def human_summary(
    analysis: Dict,
    ai_insight: Optional[str] = None,
    ai_provider: Optional[str] = None,
    diff_summary: Optional[dict] = None,
) -> str:
    posture = analysis["posture"]
    emoji   = POSTURE_EMOJI.get(posture, "⚪")
    lines   = [
        "╔══════════════════════════════════════════════════════╗",
        "║           SECURITY AUDIT REPORT                     ║",
        "╚══════════════════════════════════════════════════════╝",
        "",
        f"  {emoji}  Overall Posture : {posture}",
        f"  📊  Risk Score     : {analysis['risk_score']}",
        f"  🔍  Total Findings : {analysis['total_findings']}",
        "",
        "  Severity Breakdown:",
    ]
    for sev in SEVERITY_ORDER:
        n   = analysis["severity_counts"].get(sev, 0)
        bar = "█" * min(n, 30)
        lines.append(f"    {sev:<10} {n:>3}  {bar}")

    if diff_summary:
        lines.append("")
        lines.append("  📈  Drift vs Baseline:")
        lines.append(f"    🆕 New      : {diff_summary.get('new_count', 0)}")
        lines.append(f"    ✅ Resolved : {diff_summary.get('resolved_count', 0)}")
        lines.append(f"    ↕  Changed  : {diff_summary.get('changed_count', 0)}")

    lines.append("\n  Findings by Module:")
    for mod, count in sorted(analysis.get("by_module", {}).items(), key=lambda x: -x[1]):
        lines.append(f"    {mod:<25} {count}")
    lines.append("\n  ⚠️  Top Findings:")
    for f in analysis["top_findings"][:8]:
        lines.append(f"    [{f['severity']:<8}] {f['title']}")
        lines.append(f"               └─ {f.get('details','')[:100]}")
    lines.append("\n  🔧  Recommended Actions:")
    for i, r in enumerate(analysis["recommendations"][:8], 1):
        lines.append(f"    {i:>2}. {r}")
    if ai_insight:
        provider_label = f" [{ai_provider}]" if ai_provider else ""
        lines.append("\n" + "─" * 58)
        lines.append(f"  🤖  AI Analysis{provider_label}:")
        lines.append("─" * 58)
        for l in ai_insight.splitlines():
            lines.append(f"  {l}")
    lines.append("\n" + "═" * 58)
    return "\n".join(lines)


def telegram_summary(analysis: Dict) -> str:
    c      = analysis["severity_counts"]
    posture = analysis["posture"]
    emoji  = POSTURE_EMOJI.get(posture, "⚪")
    top    = "\n".join(f"• [{f['severity']}] {f['title']}" for f in analysis["top_findings"][:5])
    return (
        f"🛡️ *Security Scan Completed*\n"
        f"Posture: *{emoji} {posture}*\n"
        f"Risk Score: `{analysis['risk_score']}`\n"
        f"Findings: {analysis['total_findings']}\n"
        f"💀 CRITICAL: {c.get('CRITICAL',0)} | 🔴 HIGH: {c.get('HIGH',0)}\n"
        f"🟠 MEDIUM: {c.get('MEDIUM',0)} | 🟡 LOW: {c.get('LOW',0)}\n"
        f"─────────────────\n{top}\n\nUse /report for full summary."
    )
