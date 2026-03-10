from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass
class Finding:
    module: str
    title: str
    details: str
    severity: str = "LOW"
    recommendation: str = ""
    evidence: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.evidence is None:
            data["evidence"] = {}
        return data


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
