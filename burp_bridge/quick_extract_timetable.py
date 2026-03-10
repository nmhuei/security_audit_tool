#!/usr/bin/env python3
from pathlib import Path
import json, re

out = Path(__file__).resolve().parent / 'out'
rows = []
for f in sorted(out.glob('*.json')):
    try:
        data = json.loads(f.read_text())
    except Exception:
        continue
    ev = data.get('event', {})
    url = (ev.get('url') or '').lower()
    path = (ev.get('path') or '').lower()
    body = (ev.get('body') or '').lower()
    if any(k in url or k in path or k in body for k in ['timetable','schedule','calendar','erp','class']):
        rows.append((ev.get('method','GET'), ev.get('url',''), f.name))

report = out / 'timetable_candidates.md'
lines = ['# Timetable Candidate Requests', '']
if not rows:
    lines.append('- No candidate requests yet. Hãy crawl trong Burp trước.')
else:
    for m,u,n in rows:
        lines.append(f'- **{m}** {u}  (`{n}`)')
report.write_text('\n'.join(lines))
print(f'Wrote: {report}')
