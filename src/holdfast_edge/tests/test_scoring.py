from __future__ import annotations

from holdfast_edge.scoring import noisy_or
from holdfast_edge.config import default_config
from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def test_quiet_browser_is_allow(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/", headers=BROWSER))
    assert d.action == "allow"
    assert d.score < 40
    assert d.rule_id == "edge.allow"


def test_burst_raises_score(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for i in range(40):
        last = engine.observe(req("/", src_ip="203.0.113.40", headers=BROWSER))
        clock.advance(0.05)
    assert last is not None
    assert last.signals["burst"] >= 50
    assert last.score >= 40
    assert last.action in {"challenge", "deny"}
    assert last.rule_id == "edge.burst"


def test_fanout_across_paths(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for i in range(15):
        last = engine.observe(req(f"/page-{i}", src_ip="203.0.113.41", headers=BROWSER))
        clock.advance(0.2)
    assert last is not None
    assert last.signals["fanout"] >= 50
    assert last.rule_id == "edge.fanout"


def test_retry_loop_same_path(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for _ in range(8):
        last = engine.observe(req("/login", method="POST", src_ip="203.0.113.42", headers=BROWSER))
        clock.advance(0.3)
    assert last is not None
    assert last.signals["retry_loop"] >= 50
    assert last.rule_id == "edge.retry_loop"


def test_goal_seeking_numeric_walk(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for i in range(1, 8):
        last = engine.observe(req(f"/api/users/{i}", src_ip="203.0.113.43", headers=BROWSER))
        clock.advance(0.4)
    assert last is not None
    assert last.signals["goal_loop"] >= 50
    assert last.rule_id == "edge.goal_loop"


def test_ua_claim_alone_does_not_deny(clock: Clock) -> None:
    engine = make_engine(clock)
    headers = dict(BROWSER)
    headers["user-agent"] = "GPTBot/1.0 (+https://example.invalid)"
    d = engine.observe(req("/", src_ip="203.0.113.44", user_agent=headers["user-agent"], headers=headers))
    clock.advance(30)
    d2 = engine.observe(req("/", src_ip="203.0.113.44", user_agent=headers["user-agent"], headers=headers))
    assert d.action == "allow"
    assert d2.action == "allow"
    assert d.signals.get("tool_client", 0) == 0 or d.score < 40


def test_noisy_or_corroborates() -> None:
    cfg = default_config()
    one = noisy_or({"burst": 50, "fanout": 0, "retry_loop": 0, "goal_loop": 0, "tool_client": 0}, cfg)
    two = noisy_or({"burst": 50, "fanout": 50, "retry_loop": 0, "goal_loop": 0, "tool_client": 0}, cfg)
    assert 49 <= one <= 51
    assert two > one
    assert two < 100


def test_tool_shape_cannot_challenge_alone(clock: Clock) -> None:
    engine = make_engine(clock)
    thin = {"host": "example.test", "user-agent": "script"}
    d = engine.observe(req("/", src_ip="203.0.113.45", headers=thin, user_agent="script"))
    assert d.signals["tool_client"] > 0
    assert d.signals["tool_client"] <= 25
    assert d.action == "allow"
    assert d.score < 40
