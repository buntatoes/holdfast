"""In-memory sliding windows. Scoring state is not durable; a restart is a fresh slate."""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque

from holdfast_edge.config import Windows

Event = tuple[float, str, str, int | None, tuple[str, ...]]  # ts, template, method, status, ids


@dataclass
class Snapshot:
    client_fp: str
    observations: int
    first_seen: float
    last_seen: float
    burst_count: int
    distinct_paths: int
    retry_count: int
    goal_count: int
    sensitive_families: int
    numeric_id_walk: int
    header_names: tuple[str, ...]
    path_template: str
    method: str
    status: int | None
    id_walk: int


SENSITIVE_FAMILIES: tuple[tuple[str, str], ...] = (
    ("admin", "/admin"),
    ("login", "/login"),
    ("reset", "/reset"),
    ("wp", "/wp-"),
    ("env", "/.env"),
    ("git", "/.git"),
    ("graphql", "/graphql"),
    ("api", "/api/"),
    ("debug", "/debug"),
    ("internal", "/internal"),
    ("console", "/console"),
)


def family_of(path: str) -> str | None:
    low = path.lower()
    for name, prefix in SENSITIVE_FAMILIES:
        if prefix in low or low.startswith(prefix):
            return name
    return None


def _counts_as_retry(method: str, status: int | None) -> bool:
    """Repeating GET / is burst, not a retry loop. Retries are mutations or errors."""
    if status is not None:
        return int(status) >= 400
    return method in {"POST", "PUT", "PATCH", "DELETE"}


class WindowStore:
    def __init__(self, windows: Windows | None = None):
        self.windows = windows or Windows()
        self._lock = threading.Lock()
        self._events: dict[str, Deque[Event]] = defaultdict(deque)
        self._first: dict[str, float] = {}
        self._obs: dict[str, int] = defaultdict(int)

    def record(
        self,
        client_fp: str,
        path_template: str,
        method: str,
        now: float,
        status: int | None = None,
        header_names: tuple[str, ...] = (),
        id_keys: tuple[str, ...] = (),
    ) -> Snapshot:
        method_n = (method or "GET").upper()
        path_n = path_template or "/"
        horizon = max(
            self.windows.burst_s,
            self.windows.fanout_s,
            self.windows.retry_s,
            self.windows.goal_s,
        )
        with self._lock:
            q = self._events[client_fp]
            q.append((now, path_n, method_n, status, tuple(id_keys)))
            cutoff = now - horizon
            while q and q[0][0] < cutoff:
                q.popleft()
            self._obs[client_fp] += 1
            self._first.setdefault(client_fp, now)
            burst = sum(1 for ts, *_ in q if ts >= now - self.windows.burst_s)
            fan_paths = {p for ts, p, *_rest in q if ts >= now - self.windows.fanout_s}
            retry = sum(
                1
                for ts, p, m, st, _ids in q
                if ts >= now - self.windows.retry_s
                and p == path_n
                and m == method_n
                and _counts_as_retry(m, st)
            )
            goal_events = [e for e in q if e[0] >= now - self.windows.goal_s]
            families = {family_of(p) for _ts, p, *_rest in goal_events}
            families.discard(None)
            walk = 0
            by_template: dict[str, set[str]] = {}
            for _ts, p, _m, _st, ids in goal_events:
                bucket = by_template.setdefault(p, set())
                bucket.update(ids)
            if by_template:
                walk = max(len(v) for v in by_template.values())
            snap = Snapshot(
                client_fp=client_fp,
                observations=self._obs[client_fp],
                first_seen=self._first[client_fp],
                last_seen=now,
                burst_count=burst,
                distinct_paths=len(fan_paths),
                retry_count=retry,
                goal_count=len(goal_events),
                sensitive_families=len(families),
                numeric_id_walk=walk,
                header_names=header_names,
                path_template=path_n,
                method=method_n,
                status=status,
                id_walk=walk,
            )
            return snap

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._first.clear()
            self._obs.clear()
