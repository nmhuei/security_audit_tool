from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Dict
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class TelegramBot:
    def __init__(self, token: str, chat_id: str):
        self.base = f"https://api.telegram.org/bot{token}"
        self.chat_id = chat_id

    def _post(self, method: str, payload: Dict):
        data = urlencode(payload).encode()
        req = Request(f"{self.base}/{method}", data=data)
        with urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())

    def send_message(self, text: str, parse_mode: str = "Markdown"):
        return self._post("sendMessage", {"chat_id": self.chat_id, "text": text, "parse_mode": parse_mode})

    def send_document(self, path: Path):
        # Lightweight fallback: send path note if multipart isn't used.
        self.send_message(f"Report generated at: `{path}`")


def run_polling(token: str, on_scan: Callable[[], str], on_report: Callable[[], str], poll_interval: int = 3):
    base = f"https://api.telegram.org/bot{token}"
    offset = 0

    def get_updates(off: int):
        req = Request(f"{base}/getUpdates?timeout=20&offset={off}")
        with urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode())

    while True:
        try:
            data = get_updates(offset)
            for item in data.get("result", []):
                offset = item["update_id"] + 1
                msg = item.get("message", {})
                text = msg.get("text", "")
                chat_id = str(msg.get("chat", {}).get("id", ""))

                if text.startswith("/scan"):
                    out = on_scan()
                    TelegramBot(token, chat_id).send_message(out)
                elif text.startswith("/report"):
                    out = on_report()
                    TelegramBot(token, chat_id).send_message(out)
        except Exception:
            pass
        time.sleep(poll_interval)
