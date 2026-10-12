from __future__ import annotations

import json
from datetime import datetime, timezone

from .storage import Storage


def write_audit(action: str, detail: dict | None = None, storage: Storage | None = None) -> None:
    store = storage or Storage()
    store.ensure_dirs()
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": detail or {},
    }
    with store.paths.audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_audit(limit: int = 200, storage: Storage | None = None) -> list[dict]:
    store = storage or Storage()
    if not store.paths.audit_log.exists():
        return []
    lines = store.paths.audit_log.read_text(encoding="utf-8").splitlines()[-limit:]
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"ts": None, "action": "unparseable", "detail": {"line": line}})
    return entries
