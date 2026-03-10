# Burp Bridge (MVP)

## 1) Start collector

```bash
cd /home/light/Downloads/security_audit_tool
python3 burp_bridge/collector.py
```

Collector listens on `http://127.0.0.1:8765/ingest`.

## 2) Load extension in Burp

1. Burp -> **Extender** -> **Options**
2. Set **Python Environment** to `jython-standalone.jar`
3. Burp -> **Extender** -> **Extensions** -> **Add**
   - Type: `Python`
   - File: `burp_bridge/burp_extender.py`

## 3) Verify

Send a request in Proxy/Repeater.
Check outputs in:

- `burp_bridge/out/<id>.json`
- `burp_bridge/out/<id>.md`

## Notes

- Current MVP only ingests **requests**.
- Body is truncated at 4000 chars.
- You can tune scoring in `burp_bridge/rules.yaml`.
