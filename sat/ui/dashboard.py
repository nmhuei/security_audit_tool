"""dashboard.py – Real-time hacker-themed terminal dashboard using Rich."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

try:
    from rich.columns import Columns
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "bright_black",
}
SEVERITY_ICON = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "⚪",
}
POSTURE_COLOR = {
    "SECURE": "green",
    "LOW RISK": "yellow",
    "MEDIUM RISK": "dark_orange",
    "HIGH RISK": "red",
    "CRITICAL": "bold red",
}

MODULE_NAMES = {
    "port_scanner": "Port Scanner",
    "privilege_scan": "Privilege Audit",
    "filesystem_scan": "Filesystem",
    "network_scan": "Network",
    "cve_scan": "CVE Check",
    "config_scan": "Config Audit",
    "user_scan": "User Accounts",
    "secret_scan": "Secret Detector",
    "systemd_scan": "Systemd Units",
    "docker_scan": "Docker",
}


def _make_header(scan_time: str, posture: str, risk_score: int) -> Panel:
    color = POSTURE_COLOR.get(posture, "white")
    title_art = Text()
    title_art.append("⠀◆ ", style="bright_green")
    title_art.append("SECURITY AUDIT DASHBOARD", style="bold bright_green")
    title_art.append(" ◆⠀", style="bright_green")

    status = Text()
    status.append(f"  {scan_time}  ", style="dim green")
    status.append("│", style="bright_black")
    status.append(f"  Posture: ", style="white")
    status.append(f" {posture} ", style=f"bold {color} on default")
    status.append("  │", style="bright_black")
    status.append(f"  Risk Score: ", style="white")
    status.append(f"{risk_score}", style="bold red" if risk_score > 40 else "yellow")

    content = Text()
    content.append_text(title_art)
    content.append("\n")
    content.append_text(status)

    return Panel(content, style="bright_green", box=box.DOUBLE, padding=(0, 1))


def _make_severity_panel(counts: Dict[str, int], total: int) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="white", width=10)
    table.add_column(justify="right", width=4)
    table.add_column(width=28)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        pct = int((n / total * 25)) if total > 0 else 0
        bar = Text()
        bar.append("█" * pct, style=SEVERITY_COLOR.get(sev, "white"))
        bar.append("░" * (25 - pct), style="bright_black")
        icon = SEVERITY_ICON.get(sev, "")
        label = Text(f"{icon} {sev}", style=SEVERITY_COLOR.get(sev, "white"))
        table.add_row(label, str(n), bar)

    return Panel(table, title="[bright_green]SEVERITY BREAKDOWN[/]", border_style="green", box=box.SIMPLE_HEAVY)


def _make_findings_table(findings: List[dict]) -> Panel:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold green",
        border_style="bright_black",
        pad_edge=False,
    )
    table.add_column("SEV", width=8, style="bold")
    table.add_column("MODULE", width=14, style="cyan")
    table.add_column("FINDING", style="white")
    table.add_column("DETAIL", style="bright_black", max_width=55)

    for f in findings[:20]:
        sev = f.get("severity", "LOW")
        color = SEVERITY_COLOR.get(sev, "white")
        icon = SEVERITY_ICON.get(sev, "")
        mod = MODULE_NAMES.get(f.get("module", ""), f.get("module", ""))
        table.add_row(
            Text(f"{icon} {sev}", style=color),
            Text(mod, style="cyan"),
            Text(f.get("title", "")[:45], style="white"),
            Text(f.get("details", "")[:55], style="dim"),
        )

    return Panel(table, title="[bright_green]⚠ TOP FINDINGS[/]", border_style="green", box=box.SIMPLE_HEAVY)


def _make_module_status(by_module: Dict[str, int]) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", width=20)
    table.add_column(justify="right", width=4, style="white")
    table.add_column(width=3)

    for mod, count in sorted(by_module.items(), key=lambda x: -x[1]):
        name = MODULE_NAMES.get(mod, mod)
        indicator = "🔴" if count > 5 else "🟡" if count > 0 else "🟢"
        table.add_row(name, str(count), indicator)

    return Panel(table, title="[bright_green]MODULE RESULTS[/]", border_style="green", box=box.SIMPLE_HEAVY)


def _make_recs_panel(recs: List[str]) -> Panel:
    text = Text()
    for i, r in enumerate(recs[:8], 1):
        text.append(f"  {i:>2}. ", style="bright_green bold")
        text.append(r[:90] + ("\n" if i < len(recs[:8]) else ""), style="white")
    return Panel(text, title="[bright_green]🔧 RECOMMENDATIONS[/]", border_style="green", box=box.SIMPLE_HEAVY)


def _make_ai_panel(ai_insight: Optional[str]) -> Panel:
    if not ai_insight:
        text = Text("Set ANTHROPIC_API_KEY for AI-powered analysis", style="dim")
    else:
        text = Text(ai_insight[:800], style="white")
    return Panel(text, title="[bright_green]🤖 AI ANALYSIS (Claude)[/]", border_style="bright_magenta", box=box.SIMPLE_HEAVY)


def render_dashboard(
    report: dict,
    ai_insight: Optional[str] = None,
    console: Optional["Console"] = None,
) -> None:
    """Render the full hacker-themed dashboard to terminal."""
    if not RICH_AVAILABLE:
        print("[!] Install 'rich' for dashboard: pip install rich")
        return

    c = console or Console()
    analysis = report.get("analysis", {})
    findings = report.get("findings", [])
    scanned_at = report.get("scanned_at", datetime.utcnow().isoformat())[:19].replace("T", " ")

    posture = analysis.get("posture", "UNKNOWN")
    risk = analysis.get("risk_score", 0)
    counts = analysis.get("severity_counts", {})
    total = analysis.get("total_findings", 0)
    top_findings = analysis.get("top_findings", findings[:20])
    by_module = analysis.get("by_module", {})
    recs = analysis.get("recommendations", [])

    c.print(_make_header(scanned_at, posture, risk))
    c.print()

    # Two-column layout: severity + module status
    cols = Columns([
        _make_severity_panel(counts, total),
        _make_module_status(by_module),
    ], equal=True, expand=True)
    c.print(cols)
    c.print()

    c.print(_make_findings_table(top_findings))
    c.print()
    c.print(_make_recs_panel(recs))
    c.print()
    c.print(_make_ai_panel(ai_insight))
    c.print()


def render_scan_progress(
    modules: List[str],
    run_fn: Callable[[str], List],
) -> tuple[List, dict]:
    """Show live progress bar while running scans. Returns (findings, module_status)."""
    if not RICH_AVAILABLE:
        all_findings = []
        for mod in modules:
            all_findings.extend(run_fn(mod))
        return all_findings, {}

    console = Console()
    all_findings: List[dict] = []
    module_status: Dict[str, str] = {}

    console.print()
    console.print(Panel(
        "[bold bright_green]◆ INITIATING SECURITY AUDIT SEQUENCE ◆[/]\n[dim green]Scanning local machine...[/]",
        border_style="bright_green", box=box.DOUBLE, padding=(1, 4)
    ))
    console.print()

    progress = Progress(
        SpinnerColumn(style="bright_green"),
        TextColumn("[bold green]{task.description}", justify="right"),
        BarColumn(bar_width=30, style="dark_green", complete_style="bright_green"),
        TextColumn("[bright_green]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        task = progress.add_task("[bright_green]Scanning...", total=len(modules))
        for mod_name in modules:
            progress.update(task, description=f"[bright_green]{MODULE_NAMES.get(mod_name, mod_name):<22}")
            try:
                results = run_fn(mod_name)
                all_findings.extend(results)
                module_status[mod_name] = f"{len(results)} findings"
            except Exception as e:
                module_status[mod_name] = f"ERROR: {e}"
            progress.advance(task)
            time.sleep(0.05)

    return all_findings, module_status
