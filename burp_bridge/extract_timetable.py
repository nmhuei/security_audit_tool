#!/usr/bin/env python3
from pathlib import Path
import json,re

out=Path(__file__).resolve().parent/'out'
rows=[]
for f in sorted(out.glob('*.json')):
    try:d=json.loads(f.read_text())
    except:continue
    ev=d.get('event',{})
    a=d.get('analysis',{})
    url=(ev.get('url') or '').lower()
    body=(ev.get('response_body') or ev.get('body') or '')
    if any(k in url for k in ['timetable','schedule','calendar','students/learn']):
        rows.append((f.name,ev.get('kind'),ev.get('status'),ev.get('method'),ev.get('url'),len(body)))

rep=out/'timetable_auto_report.md'
lines=['# Timetable Auto Report','']
if not rows:
    lines.append('- Chưa có dữ liệu timetable trong out/*.json')
else:
    for r in rows[-100:]:
        lines.append(f'- `{r[0]}` | kind={r[1]} status={r[2]} method={r[3]} len={r[5]} | {r[4]}')
rep.write_text('\n'.join(lines))
print(rep)
