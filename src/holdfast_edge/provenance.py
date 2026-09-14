"""Operator-facing provenance. Short retention. No bodies, no raw IPs, no UAs."""

from __future__ import annotations

import json
import os
import threading
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from holdfast_edge.decisions import Decision

REQUIRED_DENY_FIELDS = ("reason", "score", "rule_id", "observed_at")


def record_from_decision(decision: Decision) -> dict[str, Any]:
    rec = {
        "id": str(uuid.uuid4()),
        "observed_at": decision.observed_at,
        "mode": decision.mode,
        "action": decision.action,
        "applied": decision.applied,
        "score": decision.score,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "client_fp": decision.client_fp,
        "path_fp": decision.path_fp,
        "signals": dict(decision.signals),
        "observations": decision.observations,
        "allowlisted": decision.allowlisted,
    }
    if decision.action == "deny":
        for key in REQUIRED_DENY_FIELDS:
            if rec.get(key) in (None, ""):
                raise ValueError(f"deny provenance missing {key}")
    return rec


class ProvenanceLog:
    """Time-bounded operational log. Not the host daemon's append-only audit chain."""

    def __init__(
        self,
        *,
        retention_hours: float = 24.0,
        path: str | Path | None = None,
        now: Any = None,
        maxlen: int = 20_000,
    ):
        self.retention_s = max(0.0, float(retention_hours) * 3600.0)
        self.path = Path(path) if path else None
        self._now = now
        self._lock = threading.Lock()
        self._items: deque[tuple[float, dict[str, Any]]] = deque(maxlen=maxlen)

    def _epoch(self) -> float:
        if self._now is not None:
            return float(self._now())
        import time

        return time.time()

    def _prune_unlocked(self, now: float) -> None:
        cutoff = now - self.retention_s
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()

    def append(self, decision: Decision) -> dict[str, Any]:
        rec = record_from_decision(decision)
        now = self._epoch()
        with self._lock:
            self._prune_unlocked(now)
            self._items.append((now, rec))
            if self.path is not None:
                self._flush_unlocked()
        return rec

    def _flush_unlocked(self) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for _ts, rec in self._items:
                fh.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(self.path)

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(0, int(limit))
        now = self._epoch()
        with self._lock:
            self._prune_unlocked(now)
            items = [rec for _ts, rec in self._items]
        if limit == 0:
            return []
        return items[-limit:]
