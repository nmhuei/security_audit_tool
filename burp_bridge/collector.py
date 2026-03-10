from __future__ import annotations
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import yaml
from analyzer import analyze_request
from reporter import build_report

BASE = Path(__file__).resolve().parent
OUT = BASE / 'out'; OUT.mkdir(exist_ok=True)
RULES = yaml.safe_load((BASE / 'rules.yaml').read_text()) or {}

def should_ignore(path):
    p = (path or '').lower()
    return any(p.endswith(ext) for ext in (RULES.get('ignore_extensions') or []))

class H(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        self.send_response(code); self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False).encode())
    def do_POST(self):
        if self.path != '/ingest':
            return self._send(404, {'error': 'not_found'})
        n = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(n).decode('utf-8', errors='ignore')
        try: event = json.loads(raw)
        except Exception: return self._send(400, {'error': 'invalid_json'})
        if should_ignore(event.get('path') or '/'):
            return self._send(200, {'status': 'ignored'})
        a = analyze_request(event, RULES)
        rid = event.get('id') or str(abs(hash((event.get('method'), event.get('url'), raw))))
        safe_rid = ''.join(c if c.isalnum() or c in ('-','_','.') else '_' for c in str(rid))[:180]
        (OUT / f'{safe_rid}.json').write_text(json.dumps({'event': event, 'analysis': a}, ensure_ascii=False, indent=2))
        (OUT / f'{safe_rid}.md').write_text(build_report(event, a))
        return self._send(200, {'status': 'ok', 'id': safe_rid, 'severity': a.get('severity'), 'risk_score': a.get('risk_score')})

def main():
    host = os.getenv('BURP_BRIDGE_HOST', '127.0.0.1')
    port = int(os.getenv('BURP_BRIDGE_PORT', '8765'))
    print(f'[burp-bridge] http://{host}:{port}')
    HTTPServer((host, port), H).serve_forever()

if __name__ == '__main__':
    main()
