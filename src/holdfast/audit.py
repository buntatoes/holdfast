"""Append-only JSONL audit log with a SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any

from holdfast.util import default_audit_path, now_iso

CHAIN_META = frozenset({"hash", "prev_hash"})
BODY_KEYS = ("id", "ts", "kind", "op", "detail", "decision", "actor", "session", "pid", "note")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def chain_hash(prev_hash: str, body: dict[str, Any]) -> str:
    payload = (prev_hash or "") + canonical_json(body)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def event_body(record: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for key in BODY_KEYS:
        if key in record and record[key] is not None:
            body[key] = record[key]
    return body


class AuditLog:
    """Thread-safe append-only JSONL. Never rewrites existing lines."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else default_audit_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    @classmethod
    def open(cls, path: str | Path | None = None) -> AuditLog:
        return cls(path)

    def _read_last_hash(self) -> str:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return ""
        if size == 0:
            return ""
        with self.path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            back = min(size, 65536)
            fh.seek(size - back)
            data = fh.read()
        lines = [ln for ln in data.splitlines() if ln.strip()]
        if not lines:
            return ""
        try:
            rec = json.loads(lines[-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ""
        if isinstance(rec, dict):
            return str(rec.get("hash") or "")
        return ""

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        body = event_body(event)
        if "ts" not in body:
            body["ts"] = now_iso()
        if "detail" not in body:
            body["detail"] = {}
        with self._lock:
            prev = self._last_hash
            digest = chain_hash(prev, body)
            record = {**body, "prev_hash": prev, "hash": digest}
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._last_hash = digest
            return record

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(0, int(limit))
        with self._lock:
            if not self.path.exists():
                return []
            text = self.path.read_text(encoding="utf-8")
        items: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if limit == 0:
            return []
        return items[-limit:]

    @property
    def last_hash(self) -> str:
        with self._lock:
            return self._last_hash
