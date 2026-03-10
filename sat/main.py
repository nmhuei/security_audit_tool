"""main.py – Security Audit Tool CLI v5."""
from __future__ import annotations

import argparse, json, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List

try:
    import yaml; _YAML = True
except ImportError:
    _YAML = False

from ai.analyzer import analyze, ai_analyze, human_summary, telegram_summary
from scanner.baseline import (save_baseline, load_baseline, diff_findings,
                               format_diff, drift_summary, list_baselines)
from scanner.common import utc_now_iso
from scanner.config_scan   import run_all as config_run
from scanner.cve_scan      import run_all as cve_run
from scanner.docker_scan   import run_all as docker_run
from scanner.filesystem_scan import run_all as fs_run
from scanner.network_scan  import run_all as net_run
from scanner.port_scanner  import scan_open_ports
from scanner.privilege_scan import run_all as priv_run
from scanner.secret_scan   import run_all as secret_run
from scanner.systemd_scan  import run_all as systemd_run
from scanner.user_scan     import run_all as user_run
from scanner.kali_tools    import run_all as kali_run, list_tools, TOOL_DESCRIPTIONS
from telegram.bot import TelegramBot, run_polling
from remediation import apply_fixes, preview_fixes, format_fix_results

try:
    from ui.dashboard import render_dashboard, render_scan_progress; _DASH = True
except ImportError:
    _DASH = False

try:
    from reporter.html_report import generate_html; _HTML = True
except ImportError:
    _HTML = False

REPORT_DIR       = Path("reports")
LAST_REPORT_JSON = REPORT_DIR / "latest_report.json"
LAST_REPORT_TXT  = REPORT_DIR / "latest_summary.txt"
LAST_REPORT_HTML = REPORT_DIR / "latest_report.html"

MODULES: dict[str, Callable[[], List]] = {
    "port_scanner":    lambda: scan_open_ports(),
    "privilege_scan":  priv_run,
    "filesystem_scan": fs_run,
    "network_scan":    net_run,
    "cve_scan":        cve_run,
    "config_scan":     config_run,
    "user_scan":       user_run,
    "secret_scan":     secret_run,
    "systemd_scan":    systemd_run,
    "docker_scan":     docker_run,
    "kali_tools":      kali_run,
}

def _load_config(path: str | None) -> dict:
    if not path or not _YAML: return {}
    try: return yaml.safe_load(Path(path).read_text()) or {}
    except Exception: return {}


def run_scan(
    timeout_per_module: int = 180,
    max_workers:  int = 8,
    skip_modules: list[str] | None = None,
    provider:     str | None = None,
    use_dashboard: bool = True,
    baseline_label: str = "default",
    deep: bool = False,
) -> tuple[dict, str | None, str | None, dict | None]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    skip = set(skip_modules or [])

    # kali_tools gets deep flag via closure
    modules = dict(MODULES)
    modules["kali_tools"] = lambda: kali_run(deep=deep)

    active = {k: v for k, v in modules.items() if k not in skip}
    findings: list[dict] = []

    if use_dashboard and _DASH:
        def _run_one(mod_name: str) -> list:
            try:   return [f.to_dict() for f in active[mod_name]()]
            except Exception as e:
                return [{"module": mod_name, "title": "Module error", "details": str(e),
                         "severity": "MEDIUM", "recommendation": "Check permissions.", "evidence": {}}]
        raw, _ = render_scan_progress(list(active.keys()), _run_one)
        findings = raw
    else:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(active))) as pool:
            futures = {pool.submit(fn): name for name, fn in active.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    findings.extend([f.to_dict() for f in fut.result(timeout=timeout_per_module)])
                except Exception as e:
                    findings.append({"module": name, "title": "Module scan failure",
                                     "details": str(e), "severity": "MEDIUM",
                                     "recommendation": "Check permissions.", "evidence": {}})

    analysis = analyze(findings)
    ai_text, ai_prov = ai_analyze(findings, provider=provider)

    diff = None
    baseline = load_baseline(baseline_label)
    if baseline is not None:
        diff = diff_findings(findings, baseline)
        analysis["drift"] = drift_summary(diff)

    report = {
        "scanned_at": utc_now_iso(),
        "scope": "local_machine_only",
        "safety": {"no_exploitation": True},
        "findings": findings,
        "analysis": analysis,
    }
    LAST_REPORT_JSON.write_text(json.dumps(report, indent=2))
    summary = human_summary(analysis, ai_text, ai_prov, diff_summary=analysis.get("drift"))
    LAST_REPORT_TXT.write_text(summary)
    if _HTML:
        generate_html(report, ai_insight=ai_text, diff=diff, output_path=LAST_REPORT_HTML)

    return report, ai_text, ai_prov, diff


# ── subcommands ────────────────────────────────────────────────────────────────

def cmd_scan(args):
    cfg      = _load_config(getattr(args, "config", None))
    scan_cfg = cfg.get("scan", {})
    timeout  = getattr(args, "timeout", None) or scan_cfg.get("timeout_per_module", 180)
    skip     = getattr(args, "skip", None) or []
    provider = getattr(args, "provider", None)
    no_dash  = getattr(args, "no_dashboard", False)
    do_fix   = getattr(args, "fix", False)
    dry_run  = getattr(args, "dry_run", False)
    save_bl  = getattr(args, "save_baseline", False)
    bl_label = getattr(args, "baseline", "default")
    deep     = getattr(args, "deep", False)

    report, ai_text, ai_prov, diff = run_scan(
        timeout_per_module=timeout, skip_modules=skip,
        provider=provider, use_dashboard=not no_dash,
        baseline_label=bl_label, deep=deep,
    )
    analysis = report["analysis"]
    findings = report["findings"]

    if _DASH and not no_dash:
        try:
            from rich.console import Console
            render_dashboard(report, ai_insight=ai_text, console=Console())
        except Exception:
            print(human_summary(analysis, ai_text, ai_prov, analysis.get("drift")))
    else:
        print(human_summary(analysis, ai_text, ai_prov, analysis.get("drift")))

    if diff:
        from scanner.baseline import load_baseline as _lb
        print(format_diff(diff))

    if save_bl:
        path = save_baseline(findings, label=bl_label)
        print(f"\n  💾  Baseline saved: {path}")

    if do_fix or dry_run:
        results = apply_fixes(findings, dry_run=dry_run, safe_only=True,
                              require_confirm=not dry_run)
        print(format_fix_results(results))

    print(f"\n  📄 JSON : {LAST_REPORT_JSON}")
    print(f"  📝 TXT  : {LAST_REPORT_TXT}")
    if _HTML: print(f"  🌐 HTML : {LAST_REPORT_HTML}")


def cmd_report(args):
    if not LAST_REPORT_TXT.exists():
        print("No report found. Run: python3 main.py scan"); return
    print(LAST_REPORT_TXT.read_text())


def cmd_diff(args):
    if not LAST_REPORT_JSON.exists():
        print("No scan yet. Run: python3 main.py scan"); return
    report   = json.loads(LAST_REPORT_JSON.read_text())
    findings = report.get("findings", [])
    label    = getattr(args, "baseline", "default")
    baseline = load_baseline(label)
    if baseline is None:
        print(f"No baseline '{label}'. Run: python3 main.py scan --save-baseline"); return
    print(format_diff(diff_findings(findings, baseline)))


def cmd_baselines(args):
    bl = list_baselines()
    if not bl:
        print("No baselines. Run: python3 main.py scan --save-baseline"); return
    print("\n  Saved baselines:\n")
    for b in bl:
        print(f"  [{b['label']}] {b['saved_at'][:19]}  —  {b['count']} findings  ({b['file']})")
    print()


def cmd_fix(args):
    if not LAST_REPORT_JSON.exists():
        print("No scan yet. Run: python3 main.py scan"); return
    findings = json.loads(LAST_REPORT_JSON.read_text()).get("findings", [])
    dry_run  = getattr(args, "dry_run", False)
    results  = apply_fixes(findings, dry_run=dry_run, safe_only=True,
                           require_confirm=not dry_run)
    print(format_fix_results(results))


def cmd_modules(args):
    print("\n  Available scanner modules:\n")
    for name in MODULES:
        print(f"  • {name}")
    print()


def cmd_tools(args):
    tools = list_tools()
    print(f"\n  External Tool Status (kali_tools):\n")
    print(f"  {'Tool':<14} {'Status':<12} Description")
    print("  " + "─" * 60)
    for name, info in tools.items():
        st = "✅ installed" if info["installed"] else "❌ missing  "
        print(f"  {name:<14} {st}  {info['description']}")
    missing = [n for n, i in tools.items() if not i["installed"]]
    if missing:
        print(f"\n  Install missing:\n  sudo apt-get install {' '.join(missing)}")
    print()


def cmd_schedule(args):
    from scheduler import (install_systemd_timer, install_cron,
                           remove_schedule, show_schedule_status)
    action = getattr(args, "action", "status")

    if action == "status":
        print(show_schedule_status())

    elif action == "install":
        freq    = getattr(args, "freq", "daily")
        deep    = getattr(args, "deep", False)
        backend = getattr(args, "backend", "systemd")
        token   = getattr(args, "telegram_token", "") or ""
        chat_id = getattr(args, "telegram_chat_id", "") or ""
        if backend == "systemd":
            ok, msg = install_systemd_timer(freq, deep=deep,
                                            telegram_token=token,
                                            telegram_chat_id=chat_id)
        else:
            ok, msg = install_cron(freq, deep=deep)
        print(("✅ " if ok else "❌ ") + msg)

    elif action == "remove":
        ok, msg = remove_schedule()
        print(("✅ " if ok else "❌ ") + msg)


def cmd_telegram(args):
    if not args.token or not args.chat_id:
        raise SystemExit("--token and --chat-id required")
    bot = TelegramBot(args.token, args.chat_id)
    if args.mode == "once":
        report, _, _, _ = run_scan(use_dashboard=False)
        bot.send_message(telegram_summary(report["analysis"]))
    else:
        def on_scan():
            r, _, _, _ = run_scan(use_dashboard=False)
            return telegram_summary(r["analysis"])
        def on_report():
            return LAST_REPORT_TXT.read_text()[:3800] if LAST_REPORT_TXT.exists() else "No report yet."
        run_polling(args.token, on_scan, on_report)


def cmd_test(args):
    """Run unit test suite."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        cwd=str(Path(__file__).parent),
    )
    sys.exit(result.returncode)


# ── argparse ───────────────────────────────────────────────────────────────────



def cmd_alert(args):
    """Alert mode: scan + notify only on new CRITICAL/HIGH findings."""
    from alert import run_alert
    import os
    tg_token = getattr(args, "telegram_token", None) or os.environ.get("TELEGRAM_TOKEN", "")
    tg_chat  = getattr(args, "telegram_chat_id", None) or os.environ.get("TELEGRAM_CHAT_ID", "")
    rc = run_alert(
        min_severity   = getattr(args, "min_severity", "HIGH"),
        baseline_label = getattr(args, "baseline", "default"),
        deep           = getattr(args, "deep", False),
        dry_run        = getattr(args, "dry_run", False),
        telegram_token = tg_token if getattr(args, "telegram", False) else "",
        telegram_chat  = tg_chat  if getattr(args, "telegram", False) else "",
        email_to       = getattr(args, "email", "") or "",
        webhook_url    = getattr(args, "webhook", "") or "",
        always_notify  = getattr(args, "always_notify", False),
    )
    import sys; sys.exit(rc if rc == 2 else 0)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="🔒 Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py scan                            # full scan
  python3 main.py scan --deep                     # + nmap vuln scripts, rkhunter, tiger, aide
  python3 main.py scan --save-baseline            # save snapshot for drift detection
  python3 main.py scan --fix                      # auto-fix safe issues
  python3 main.py scan --fix --dry-run            # preview fixes
  python3 main.py diff                            # show drift vs baseline
  python3 main.py fix --dry-run                   # preview fixes on last scan
  python3 main.py schedule install --freq daily   # install systemd timer
  python3 main.py schedule install --backend cron # use cron instead
  python3 main.py test                            # run unit tests
        """,
    )
    p.add_argument("--config", "-c")
    sub = p.add_subparsers(required=True, title="commands")

    # scan
    sp = sub.add_parser("scan")
    sp.add_argument("--skip", nargs="*", metavar="MODULE")
    sp.add_argument("--timeout", type=int)
    sp.add_argument("--no-dashboard", action="store_true")
    sp.add_argument("--provider", help="LLM provider")
    sp.add_argument("--save-baseline", action="store_true")
    sp.add_argument("--baseline", default="default")
    sp.add_argument("--fix", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--deep", action="store_true",
                    help="Enable slow/thorough checks: nmap vuln scripts, rkhunter, tiger, aide")
    sp.set_defaults(func=cmd_scan)

    # simple commands
    for name, fn, help_text in [
        ("report",    cmd_report,    "Show latest summary"),
        ("modules",   cmd_modules,   "List scanner modules"),
        ("tools",     cmd_tools,     "Show external tool availability"),
        ("test",      cmd_test,      "Run unit test suite"),
    ]:
        xp = sub.add_parser(name, help=help_text)
        xp.set_defaults(func=fn)

    # diff
    dp = sub.add_parser("diff", help="Drift vs baseline")
    dp.add_argument("--baseline", default="default")
    dp.set_defaults(func=cmd_diff)

    # baselines
    bp = sub.add_parser("baselines", help="List saved baselines")
    bp.set_defaults(func=cmd_baselines)

    # fix
    fp = sub.add_parser("fix", help="Apply fixes to last scan")
    fp.add_argument("--dry-run", action="store_true")
    fp.set_defaults(func=cmd_fix)

    # schedule
    scp = sub.add_parser("schedule", help="Manage periodic scanning")
    scp.add_argument("action", choices=["install","remove","status"], default="status", nargs="?")
    scp.add_argument("--freq", choices=["daily","weekly","hourly","monthly"], default="daily")
    scp.add_argument("--backend", choices=["systemd","cron"], default="systemd")
    scp.add_argument("--deep", action="store_true")
    scp.add_argument("--telegram-token", help="Send alerts to Telegram")
    scp.add_argument("--telegram-chat-id")
    scp.set_defaults(func=cmd_schedule)

    # telegram
    tp = sub.add_parser("telegram")
    tp.add_argument("--token"); tp.add_argument("--chat-id")
    tp.add_argument("--mode", choices=["once","poll"], default="once")
    tp.set_defaults(func=cmd_telegram)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
