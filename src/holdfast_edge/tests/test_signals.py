from __future__ import annotations

from holdfast_edge.config import default_config
from holdfast_edge.signals import BROWSERISH, tool_client_score
from holdfast_edge.store import Snapshot
from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def _snap(names: tuple[str, ...]) -> Snapshot:
    return Snapshot(
        client_fp="x",
        observations=1,
        first_seen=0,
        last_seen=0,
        burst_count=1,
        distinct_paths=1,
        retry_count=1,
        goal_count=1,
        sensitive_families=0,
        numeric_id_walk=0,
        header_names=names,
        path_template="/",
        method="GET",
        status=None,
        id_walk=0,
    )


def test_tool_client_uses_header_names_not_ua_text() -> None:
    cfg = default_config()
    thin = tool_client_score(_snap(("host", "user-agent")), cfg)
    full = tool_client_score(_snap(tuple(BROWSERISH) + ("host", "user-agent")), cfg)
    empty = tool_client_score(_snap(()), cfg)
    assert thin > full
    assert full == 0
    assert empty == 0  # missing data is not evidence
    assert thin <= 25


def test_sensitive_path_spray(clock: Clock) -> None:
    engine = make_engine(clock)
    paths = ["/admin", "/login", "/.env", "/graphql", "/debug"]
    last = None
    for p in paths:
        last = engine.observe(req(p, src_ip="203.0.113.80", headers=BROWSER))
        clock.advance(0.5)
    assert last.signals["goal_loop"] >= 50


def test_path_redaction_keeps_goal_walk(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for i in range(1, 8):
        last = engine.observe(
            req(f"/accounts/{i}/settings", src_ip="203.0.113.81", headers=BROWSER)
        )
        clock.advance(0.4)
    assert last.signals["goal_loop"] >= 50
