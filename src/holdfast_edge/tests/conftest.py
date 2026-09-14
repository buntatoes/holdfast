from __future__ import annotations

import pytest

from holdfast_edge.config import from_dict
from holdfast_edge.engine import EdgeEngine


class Clock:
    def __init__(self, start: float = 1_700_000_000.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make_engine(clock: Clock, mode: str = "enforce", **overrides) -> EdgeEngine:
    data = {"mode": mode, "salt": "test-salt"}
    data.update(overrides)
    cfg = from_dict(data)
    return EdgeEngine(cfg, now=clock.now)


def req(
    path: str = "/",
    *,
    method: str = "GET",
    src_ip: str = "203.0.113.10",
    user_agent: str = "Mozilla/5.0",
    headers: dict | None = None,
    host: str = "example.test",
    **extra,
) -> dict:
    payload = {
        "method": method,
        "path": path,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "host": host,
        "headers": headers or {"host": host, "user-agent": user_agent, "accept": "*/*"},
    }
    payload.update(extra)
    return payload


BROWSER = {
    "host": "example.test",
    "user-agent": "Mozilla/5.0",
    "accept": "text/html",
    "accept-language": "en",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-ch-ua": '"Chromium"',
    "referer": "https://example.test/",
    "cookie": "sid=1",
}
