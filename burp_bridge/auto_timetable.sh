#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$BASE_DIR/.." && pwd)"
OUT_DIR="$BASE_DIR/out"
EMIU_DIR="/home/light/Documents/timetable/emiu"

mkdir -p "$OUT_DIR" "$EMIU_DIR"

# 1) Ensure bridge is running
if ! ss -ltn 2>/dev/null | grep -q '127.0.0.1:8765'; then
  echo "🌸 Bridge chưa chạy, tự bật lên..."
  nohup "$BASE_DIR/run_mvp.sh" >/tmp/burp_bridge.log 2>&1 &
  sleep 1
fi

if ! ss -ltn 2>/dev/null | grep -q '127.0.0.1:8765'; then
  echo "❌ Không bật được bridge 127.0.0.1:8765"
  exit 1
fi

# 2) Replay latest timetable request from captured Burp data and parse/update files
python3 - <<'PY'
import json, ssl, urllib.request
from pathlib import Path
from datetime import datetime, UTC

out_dir = Path('/home/light/Downloads/security_audit_tool/burp_bridge/out')
emiu_dir = Path('/home/light/Documents/timetable/emiu')

# pick latest timetable request captured by Burp bridge
candidates = sorted(out_dir.glob('POST__student-services_api_v2_timetables_query-student-timetable-in-range_*json'), key=lambda p: p.stat().st_mtime, reverse=True)
req = None
for f in candidates:
    try:
        d = json.loads(f.read_text())
    except Exception:
        continue
    if not isinstance(d, dict):
        continue
    ev = d.get('event', {})
    if ev.get('kind') == 'request' and ev.get('method') == 'POST':
        req = ev
        break

if not req:
    raise SystemExit('❌ Chưa có request timetable trong burp_bridge/out. Hãy mở trang timetable 1 lần rồi chạy lại.')

url = req['url']
body = (req.get('body') or '').encode('utf-8')
headers = dict(req.get('headers') or {})
for k in list(headers.keys()):
    if k.lower() in ['content-length', 'host', 'accept-encoding', 'connection']:
        headers.pop(k, None)

request = urllib.request.Request(url, data=body, headers=headers, method='POST')
with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=30) as r:
    raw = r.read().decode('utf-8', errors='ignore')

# Save raw
(out_dir / 'timetable_live_full.json').write_text(raw)
arr = json.loads(raw)

# Parse slots from calendars
slots = []
for e in arr:
    for c in (e.get('calendars') or []):
        if isinstance(c, str):
            try:
                c = json.loads(c)
            except Exception:
                continue
        dt = c.get('date')
        if isinstance(dt, (int, float)):
            dt = datetime.fromtimestamp(dt / 1000).strftime('%Y-%m-%d')
        slots.append({
            'date': dt,
            'course': e.get('name') or e.get('courseName') or '',
            'courseId': e.get('courseId') or '',
            'classCode': e.get('classId') or '',
            'location': c.get('place') or '',
            'lecturer': ', '.join(c.get('teacherNames') or []),
            'fromPeriod': c.get('from'),
            'toPeriod': c.get('to'),
            'lessonType': c.get('lessonType') or ''
        })

# dedup
uniq = []
seen = set()
for s in slots:
    k = (s['date'], s['courseId'], s['classCode'], s['fromPeriod'], s['toPeriod'], s['location'])
    if k in seen:
        continue
    seen.add(k)
    uniq.append(s)
uniq.sort(key=lambda x: (x['date'] or '', x['fromPeriod'] or 99, x['course']))

# USTH period mapping (current)
start_map = {1:'07:30',2:'08:25',3:'09:25',4:'10:25',5:'11:20',6:'13:00',7:'13:55',8:'14:50',9:'15:50',10:'16:45',11:'18:00',12:'18:55'}
end_map   = {1:'08:20',2:'09:15',3:'10:15',4:'11:15',5:'12:10',6:'13:50',7:'14:45',8:'15:45',9:'16:40',10:'17:40',11:'18:50',12:'19:45'}

final = []
for s in uniq:
    fp, tp = s.get('fromPeriod'), s.get('toPeriod')
    final.append({
        'date': s.get('date'),
        'course': f"{s.get('classCode','')} - {s.get('course','')} - {s.get('courseId','')}",
        'start': start_map.get(fp, ''),
        'end': end_map.get(tp, ''),
        'location': s.get('location',''),
        'lecturer': s.get('lecturer',''),
        'format': 'Lý thuyết' if s.get('lessonType') == 'LT' else (s.get('lessonType') or ''),
        'period': f"{fp}-{tp}" if fp and tp else ''
    })

# save parsed helper
(out_dir / 'timetable_parsed.json').write_text(json.dumps(uniq, ensure_ascii=False, indent=2))
(out_dir / 'timetable_parsed.md').write_text('# Timetable Parsed\n\n' + '\n'.join(
    f"- {r['date']} | tiết {r['fromPeriod']}-{r['toPeriod']} | {r['course']} ({r['courseId']}) | {r['location']} | {r['lecturer']}" for r in uniq
))

# backups + update emiu files
json_path = emiu_dir / 'emiu-timetable-2026-03.json'
ics_path = emiu_dir / 'emiu-timetable-2026-03.ics'
stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
if json_path.exists():
    (emiu_dir / f'emiu-timetable-2026-03.json.bak-{stamp}').write_text(json_path.read_text())
if ics_path.exists():
    (emiu_dir / f'emiu-timetable-2026-03.ics.bak-{stamp}').write_text(ics_path.read_text())

json_path.write_text(json.dumps(final, ensure_ascii=False, indent=2))

lines = ['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//OpenClaw//Emiu Timetable//EN','CALSCALE:GREGORIAN']
for i, e in enumerate(final, 1):
    if not (e['date'] and e['start'] and e['end']):
        continue
    ds = e['date'].replace('-', '') + e['start'].replace(':', '') + '00'
    de = e['date'].replace('-', '') + e['end'].replace(':', '') + '00'
    lines += [
        'BEGIN:VEVENT',
        f'UID:emiu-{i}@openclaw',
        f'DTSTAMP:{datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")}',
        f'DTSTART;TZID=Asia/Ho_Chi_Minh:{ds}',
        f'DTEND;TZID=Asia/Ho_Chi_Minh:{de}',
        f'SUMMARY:{e["course"]}',
        f'LOCATION:{e["location"]}',
        f'DESCRIPTION:Giảng viên: {e["lecturer"]}\\nHình thức: {e["format"]}\\nTiết: {e["period"]}',
        'END:VEVENT'
    ]
lines.append('END:VCALENDAR')
ics_path.write_text('\n'.join(lines))

print(f'✅ Done. raw_events={len(arr)} parsed_slots={len(uniq)} final_events={len(final)}')
print(f'📁 {json_path}')
print(f'📁 {ics_path}')
PY
