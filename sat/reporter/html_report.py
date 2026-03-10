"""html_report.py – Dark-theme HTML report with diff/drift visualization."""
from __future__ import annotations

import html as _html
try:
    from scanner.baseline import _finding_key as _fkey
except ImportError:
    def _fkey(f): return ""
from pathlib import Path
from typing import Optional

SEV_COLOR = {"CRITICAL":"#ff2244","HIGH":"#ff6600","MEDIUM":"#ffbb00","LOW":"#777777"}
POSTURE_COLOR = {"SECURE":"#00ff88","LOW RISK":"#aadd00","MEDIUM RISK":"#ff8800",
                 "HIGH RISK":"#ff3300","CRITICAL":"#ff0000"}

def _badge(sev: str, text: str | None = None) -> str:
    c = SEV_COLOR.get(sev, "#666")
    return (f'<span class="badge" style="background:{c};color:#000">'
            f'{text or sev}</span>')

def _diff_badge(kind: str) -> str:
    styles = {
        "NEW":      "background:#ff2244;color:#fff",
        "RESOLVED": "background:#00cc66;color:#000",
        "CHANGED":  "background:#ffaa00;color:#000",
        "SAME":     "background:#333;color:#888",
    }
    return f'<span class="badge" style="{styles.get(kind,"")}">{"▲" if kind=="NEW" else "✓" if kind=="RESOLVED" else "↕" if kind=="CHANGED" else ""} {kind}</span>'

def _e(s: str) -> str:
    return _html.escape(str(s))

def generate_html(
    report:      dict,
    ai_insight:  Optional[str] = None,
    diff:        Optional[dict] = None,    # from baseline.diff_findings()
    output_path: Optional[Path] = None,
) -> str:
    analysis   = report.get("analysis", {})
    findings   = report.get("findings", [])
    scanned_at = report.get("scanned_at", "")[:19].replace("T", " ")
    posture    = analysis.get("posture", "UNKNOWN")
    risk_score = analysis.get("risk_score", 0)
    counts     = analysis.get("severity_counts", {})
    top_f      = analysis.get("top_findings", findings[:20])
    recs       = analysis.get("recommendations", [])
    by_module  = analysis.get("by_module", {})
    drift      = analysis.get("drift", {})
    posture_c  = POSTURE_COLOR.get(posture, "#888")
    total      = max(analysis.get("total_findings", 1), 1)

    # ── Severity bar ──────────────────────────────────────────────────────────
    bar = ""
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        n = counts.get(sev, 0)
        if n:
            pct = max(round(n/total*100), 2)
            c   = SEV_COLOR[sev]
            bar += (f'<div style="flex:{pct};background:{c};height:100%;'
                    f'display:flex;align-items:center;justify-content:center;'
                    f'font-size:11px;font-weight:bold;color:#000;min-width:{pct}%">'
                    f'{sev[0]}&nbsp;{n}</div>')

    # ── Risk score color ──────────────────────────────────────────────────────
    score_c = "#ff2244" if risk_score>80 else "#ff6600" if risk_score>40 else "#ffbb00" if risk_score>20 else "#00ff88"

    # ── Module rows ───────────────────────────────────────────────────────────
    mod_rows = ""
    for mod, cnt in sorted(by_module.items(), key=lambda x: -x[1]):
        ic = "🔴" if cnt>5 else "🟡" if cnt>0 else "🟢"
        mod_rows += f"<tr><td style='color:#88ccff'>{_e(mod)}</td><td>{cnt}</td><td>{ic}</td></tr>"

    # ── Findings table (annotated with diff status) ───────────────────────────
    # Build lookup of diff keys
    diff_status: dict[str, tuple[str,str]] = {}  # _key → (status, prev_sev)
    if diff:
        for f in diff.get("new", []):
            diff_status[f.get("_key","")] = ("NEW", "")
        for f in diff.get("resolved", []):
            diff_status[f.get("_key","")] = ("RESOLVED", "")
        for f in diff.get("changed", []):
            diff_status[f.get("_key","")] = ("CHANGED", f.get("_prev_severity",""))

    f_rows = ""
    for f in top_f[:50]:
        sev  = f.get("severity","LOW")
        # Compute key if not already present (findings list vs diff list)
        key  = f.get("_key","") or (_fkey(f) if diff else "")
        status, prev_sev = diff_status.get(key, ("",""))
        status_html = (_diff_badge(status) + (f" <small style='color:#888'>was {prev_sev}</small>" if prev_sev else "")) if status else ""
        row_bg = ""
        if status == "NEW":      row_bg = "background:rgba(255,34,68,0.08)"
        elif status == "RESOLVED": row_bg = "background:rgba(0,204,102,0.08)"
        elif status == "CHANGED":  row_bg = "background:rgba(255,170,0,0.08)"
        f_rows += f"""
        <tr style="{row_bg}">
          <td>{_badge(sev)}</td>
          <td style="color:#88aaff;font-size:12px">{_e(f.get("module",""))}</td>
          <td style="color:#eee">{_e(f.get("title",""))}</td>
          <td style="color:#999;font-size:12px">{_e(f.get("details","")[:130])}</td>
          <td>{status_html}</td>
        </tr>"""

    # ── Recommendations ───────────────────────────────────────────────────────
    recs_html = "".join(f"<li>{_e(r)}</li>" for r in recs[:10])

    # ── Drift panel (only when diff available) ────────────────────────────────
    drift_html = ""
    if drift and (drift.get("new_count",0) + drift.get("resolved_count",0) > 0):
        new_c  = drift.get("new_count",0)
        res_c  = drift.get("resolved_count",0)
        chg_c  = drift.get("changed_count",0)
        crit_n = drift.get("new_critical",0)
        high_n = drift.get("new_high",0)

        # Mini timeline bars
        new_pct = min(new_c * 10, 100)
        res_pct = min(res_c * 10, 100)

        new_findings_html = ""
        for f in drift.get("new_findings", [])[:10]:
            sev = f.get("severity","?")
            new_findings_html += (
                f"<li style='margin:4px 0'>{_badge(sev)} "
                f"<span style='color:#ccc'>{_e(f.get('title','')[:80])}</span></li>"
            )

        drift_html = f"""
        <div class="card full-width" style="border-color:#ff6600;margin-bottom:16px">
          <h2 style="color:#ff8800">📈 BASELINE DRIFT ANALYSIS</h2>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:12px 0">
            <div style="text-align:center;background:#1a0a00;border-radius:6px;padding:12px">
              <div style="font-size:28px;font-weight:bold;color:#ff4444">{new_c}</div>
              <div style="font-size:11px;color:#888">NEW FINDINGS</div>
              <div style="font-size:10px;color:#ff6666">CRITICAL:{crit_n} HIGH:{high_n}</div>
            </div>
            <div style="text-align:center;background:#001a00;border-radius:6px;padding:12px">
              <div style="font-size:28px;font-weight:bold;color:#00cc66">{res_c}</div>
              <div style="font-size:11px;color:#888">RESOLVED</div>
            </div>
            <div style="text-align:center;background:#1a1000;border-radius:6px;padding:12px">
              <div style="font-size:28px;font-weight:bold;color:#ffaa00">{chg_c}</div>
              <div style="font-size:11px;color:#888">SEVERITY CHANGED</div>
            </div>
            <div style="text-align:center;background:#0d0d0d;border-radius:6px;padding:12px">
              <div style="font-size:28px;font-weight:bold;color:#888">{drift.get("unchanged_count",0)}</div>
              <div style="font-size:11px;color:#555">UNCHANGED</div>
            </div>
          </div>

          <!-- Progress bars -->
          <div style="margin:12px 0">
            <div style="display:flex;align-items:center;gap:8px;margin:6px 0">
              <div style="color:#ff4444;font-size:12px;width:80px">New</div>
              <div style="flex:1;background:#1a0000;height:14px;border-radius:7px;overflow:hidden">
                <div style="width:{new_pct}%;background:#ff4444;height:100%;transition:width 1s"></div>
              </div>
              <div style="color:#ff4444;font-size:12px;width:30px">{new_c}</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin:6px 0">
              <div style="color:#00cc66;font-size:12px;width:80px">Resolved</div>
              <div style="flex:1;background:#001a00;height:14px;border-radius:7px;overflow:hidden">
                <div style="width:{res_pct}%;background:#00cc66;height:100%;transition:width 1s"></div>
              </div>
              <div style="color:#00cc66;font-size:12px;width:30px">{res_c}</div>
            </div>
          </div>

          {'<div><h3 style="color:#ff6666;font-size:13px;margin:12px 0 6px">🆕 New Findings:</h3><ul style="list-style:none;padding:0">' + new_findings_html + '</ul></div>' if new_findings_html else ''}
        </div>"""

    # ── AI insight ────────────────────────────────────────────────────────────
    ai_html = ""
    if ai_insight:
        escaped = _e(ai_insight).replace("\n","<br>").replace("**","<strong>").replace("**","</strong>")
        ai_html = f"""
        <div class="card full-width" style="border-color:#9944ff;background:#0d0020">
          <h2 style="color:#bb77ff">🤖 AI Security Analysis</h2>
          <div style="color:#ddd;line-height:1.8;font-size:13px;margin-top:8px">{escaped}</div>
        </div>"""

    # ── Resolved findings (if diff) ───────────────────────────────────────────
    resolved_html = ""
    if diff and diff.get("resolved"):
        rows = ""
        for f in diff["resolved"][:10]:
            sev = f.get("severity","LOW")
            rows += (f"<tr style='opacity:0.6'><td>{_badge(sev)}</td>"
                     f"<td style='color:#88aaff;font-size:12px'>{_e(f.get('module',''))}</td>"
                     f"<td style='color:#888;text-decoration:line-through'>{_e(f.get('title',''))}</td>"
                     f"<td>{_diff_badge('RESOLVED')}</td></tr>")
        resolved_html = f"""
        <div class="card full-width" style="border-color:#00cc66;margin-bottom:16px">
          <h2 style="color:#00cc66">✅ RESOLVED FINDINGS ({len(diff['resolved'])} fixed)</h2>
          <table><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Status</th></tr>
          {rows}</table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit – {scanned_at}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#070710;color:#eee;font-family:'Courier New',monospace;padding:24px;line-height:1.5}}
  h1{{color:#00ff88;font-size:22px;letter-spacing:3px;margin-bottom:4px}}
  h2{{color:#00cc66;font-size:14px;margin-bottom:10px;letter-spacing:1px;text-transform:uppercase}}
  h3{{color:#aaa;font-size:13px}}
  .header{{border:1px solid #00ff88;border-radius:8px;padding:18px 24px;margin-bottom:20px;background:#030d03}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}}
  .card{{background:#0b120b;border:1px solid #1a3a1a;border-radius:8px;padding:16px}}
  .full-width{{grid-column:1/-1}}
  .posture{{color:{posture_c};font-size:26px;font-weight:bold;margin:6px 0}}
  .score{{font-size:32px;font-weight:bold;color:{score_c}}}
  .meta{{color:#666;font-size:12px;margin-top:4px}}
  .sev-bar{{display:flex;height:26px;border-radius:4px;overflow:hidden;margin:10px 0}}
  .badge{{padding:2px 7px;border-radius:3px;font-size:11px;font-weight:bold;white-space:nowrap}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th{{color:#00ff88;text-align:left;padding:8px 10px;border-bottom:1px solid #1a3a1a;font-size:11px}}
  td{{padding:6px 10px;border-bottom:1px solid #0d150d;vertical-align:top}}
  tr:hover td{{background:#0d150d}}
  ol,ul{{padding-left:18px}}
  li{{margin:4px 0;font-size:13px}}
  footer{{color:#333;font-size:11px;margin-top:32px;text-align:center;border-top:1px solid #111;padding-top:12px}}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ SECURITY AUDIT REPORT</h1>
  <div class="meta">Scanned: {scanned_at} &nbsp;|&nbsp; Local machine defensive scan</div>
</div>

{drift_html}

<div class="grid">

  <div class="card">
    <h2>Overall Posture</h2>
    <div class="posture">{posture}</div>
    <div style="margin:8px 0">Risk Score: <span class="score">{risk_score}</span></div>
    <div class="meta">Total Findings: {analysis.get("total_findings",0)}</div>
  </div>

  <div class="card">
    <h2>Severity Breakdown</h2>
    <div class="sev-bar">{bar}</div>
    <table>
      {"".join(f'<tr><td style="color:{SEV_COLOR.get(s,"#888")}">{s}</td><td style="text-align:right;color:#eee;font-weight:bold">{counts.get(s,0)}</td></tr>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
    </table>
  </div>

  <div class="card">
    <h2>Module Results</h2>
    <table><tr><th>Module</th><th>Findings</th><th></th></tr>{mod_rows}</table>
  </div>

  <div class="card">
    <h2>🔧 Recommendations</h2>
    <ol style="color:#ccc">{recs_html}</ol>
  </div>

  <div class="card full-width">
    <h2>⚠ Findings {f'(annotated with drift status)' if diff else ''}</h2>
    <table>
      <tr><th>Sev</th><th>Module</th><th>Finding</th><th>Detail</th><th>{'Drift' if diff else ''}</th></tr>
      {f_rows}
    </table>
  </div>

  {resolved_html}

  {ai_html}

</div>

<footer>Security Audit Tool &nbsp;|&nbsp; Authorized local use only &nbsp;|&nbsp; {scanned_at}</footer>
</body>
</html>"""

    if output_path:
        output_path.write_text(html, encoding="utf-8")
    return html
