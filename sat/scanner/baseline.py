"""baseline.py – Collision-resistant snapshot & drift detection."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

BASELINE_DIR = Path("reports/baselines")

# ── collision-resistant fingerprinting ────────────────────────────────────────

def _normalize(s: str) -> str:
    """Strip volatile parts: paths with timestamps, port numbers, IPs, sizes."""
    s = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", s)   # IPs
    s = re.sub(r"\bport\s+\d+\b", "port <N>", s, flags=re.I)             # "port 22"
    s = re.sub(r":\d{2,5}\b", ":<PORT>", s)                              # :8080
    s = re.sub(r"\b\d{4,}\b", "<N>", s)                                  # big numbers
    s = re.sub(r"20\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d\S*", "<TS>", s)    # timestamps
    s = re.sub(r"size=\d+B?", "size=<N>", s)                             # size=1234B
    return s.strip()

def _extract_evidence_key(f: dict) -> str:
    """Pull stable identifiers from evidence dict."""
    ev = f.get("evidence") or {}
    parts = []
    # Prefer stable evidence fields over raw details string
    for key in ("vuln_id", "cve", "package", "path", "port", "pattern",
                "script", "group", "user", "file", "socket"):
        val = ev.get(key)
        if val:
            parts.append(f"{key}={val}")
    return "|".join(parts)

def _finding_key(f: dict) -> str:
    """
    Stable collision-resistant fingerprint.
    Uses: module + normalized_title + evidence_key
    Falls back to normalized details only when no structured evidence.
    """
    module = f.get("module", "")
    title  = _normalize(f.get("title", ""))
    ev_key = _extract_evidence_key(f)

    if ev_key:
        raw = f"{module}|{title}|{ev_key}"
    else:
        # Normalize details to strip volatile tokens
        details = _normalize(f.get("details", ""))[:150]
        raw = f"{module}|{title}|{details}"

    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _annotate(findings: list[dict]) -> list[dict]:
    return [{**f, "_key": _finding_key(f)} for f in findings]


# ── save / load ────────────────────────────────────────────────────────────────

def save_baseline(findings: list[dict], label: str = "default") -> Path:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = BASELINE_DIR / f"{label}_{ts}.json"
    ann  = _annotate(findings)
    data = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "label":    label,
        "count":    len(ann),
        "findings": ann,
    }
    path.write_text(json.dumps(data, indent=2))
    (BASELINE_DIR / f"{label}_latest.json").write_text(json.dumps(data, indent=2))
    return path


def load_baseline(label: str = "default") -> list[dict] | None:
    latest = BASELINE_DIR / f"{label}_latest.json"
    if not latest.exists():
        return None
    try:
        return json.loads(latest.read_text()).get("findings", [])
    except Exception:
        return None


def list_baselines() -> list[dict]:
    if not BASELINE_DIR.exists():
        return []
    results = []
    for p in sorted(BASELINE_DIR.glob("*.json")):
        if p.name.endswith("_latest.json"):
            continue
        try:
            d = json.loads(p.read_text())
            results.append({"file": p.name, "label": d.get("label", ""),
                            "saved_at": d.get("saved_at", ""), "count": d.get("count", 0)})
        except Exception:
            pass
    return results


# ── diff engine ────────────────────────────────────────────────────────────────

def diff_findings(current: list[dict], baseline: list[dict]) -> Dict[str, list[dict]]:
    cur  = {f["_key"]: f for f in _annotate(current)}
    base = {f["_key"]: f for f in _annotate(baseline)}

    new_keys      = set(cur) - set(base)
    resolved_keys = set(base) - set(cur)
    common        = set(cur) & set(base)

    changed, unchanged = [], []
    for k in common:
        c, b = cur[k], base[k]
        if c.get("severity") != b.get("severity"):
            changed.append({**c, "_prev_severity": b.get("severity")})
        else:
            unchanged.append(c)

    # Sort new by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    new_sorted = sorted(
        [cur[k] for k in new_keys],
        key=lambda f: sev_rank.get(f.get("severity", "LOW"), 3)
    )

    return {
        "new":       new_sorted,
        "resolved":  [base[k] for k in resolved_keys],
        "changed":   changed,
        "unchanged": unchanged,
    }


def format_diff(diff: Dict[str, list[dict]], baseline_date: str = "") -> str:
    new, resolved, changed, unchanged = (
        diff.get("new", []), diff.get("resolved", []),
        diff.get("changed", []), diff.get("unchanged", []),
    )
    crit_new = sum(1 for f in new if f.get("severity") == "CRITICAL")
    high_new = sum(1 for f in new if f.get("severity") == "HIGH")

    lines = [
        "╔══════════════════════════════════════════════════════╗",
        "║           BASELINE DRIFT REPORT                     ║",
        "╚══════════════════════════════════════════════════════╝",
        f"  Compared to baseline: {baseline_date}",
        f"  🆕 New      : {len(new):>4}  (CRITICAL:{crit_new} HIGH:{high_new})  {'🔴 REGRESSION' if new else '✅'}",
        f"  ✅ Resolved : {len(resolved):>4}  {'✅ PROGRESS' if resolved else ''}",
        f"  ↕  Changed  : {len(changed):>4}",
        f"  ═  Unchanged: {len(unchanged):>4}", "",
    ]
    if new:
        lines.append("  🆕  NEW FINDINGS:")
        for f in new[:15]:
            lines.append(f"    [{f.get('severity','?'):<8}] {f.get('module','')}: {f.get('title','')}")
            lines.append(f"               └─ {f.get('details','')[:90]}")
        lines.append("")
    if resolved:
        lines.append("  ✅  RESOLVED:")
        for f in resolved[:10]:
            lines.append(f"    [{f.get('severity','?'):<8}] {f.get('module','')}: {f.get('title','')}")
        lines.append("")
    if changed:
        lines.append("  ↕   SEVERITY CHANGED:")
        for f in changed[:10]:
            lines.append(
                f"    {f.get('module','')}: {f.get('title','')} "
                f"[{f.get('_prev_severity','')} → {f.get('severity','')}]"
            )
        lines.append("")
    lines.append("═" * 58)
    return "\n".join(lines)


def drift_summary(diff: Dict[str, list[dict]]) -> dict:
    return {
        "new_count":       len(diff.get("new", [])),
        "resolved_count":  len(diff.get("resolved", [])),
        "changed_count":   len(diff.get("changed", [])),
        "unchanged_count": len(diff.get("unchanged", [])),
        "new_critical":    sum(1 for f in diff.get("new", []) if f.get("severity") == "CRITICAL"),
        "new_high":        sum(1 for f in diff.get("new", []) if f.get("severity") == "HIGH"),
        "regressed":       len(diff.get("new", [])) > 0,
        "improved":        len(diff.get("resolved", [])) > 0,
        "new_findings":    diff.get("new", [])[:10],    # for alert use
    }
