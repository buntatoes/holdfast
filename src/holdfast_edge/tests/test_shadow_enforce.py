from __future__ import annotations

from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def _burst(clock: Clock, mode: str, ip: str):
    engine = make_engine(clock, mode=mode)
    last = None
    for _ in range(40):
        last = engine.observe(req("/", src_ip=ip, headers=BROWSER))
        clock.advance(0.05)
    return last


def test_shadow_logs_but_always_applies_allow(clock: Clock) -> None:
    last = _burst(clock, "shadow", "203.0.113.70")
    assert last.mode == "shadow"
    assert last.action == "challenge"  # would-challenge
    assert last.applied == "allow"


def test_enforce_applies_scored_action(clock: Clock) -> None:
    last = _burst(clock, "enforce", "203.0.113.71")
    assert last.mode == "enforce"
    assert last.action == "challenge"
    assert last.applied == "challenge"


def test_dry_run_alias_is_shadow(clock: Clock) -> None:
    engine = make_engine(clock, mode="dry-run")
    assert engine.config.mode == "shadow"
    last = None
    for _ in range(40):
        last = engine.observe(req("/", src_ip="203.0.113.72", headers=BROWSER))
        clock.advance(0.05)
    assert last.applied == "allow"


def test_shadow_and_enforce_same_score(clock: Clock) -> None:
    shadow = _burst(Clock(), "shadow", "203.0.113.73")
    enforce = _burst(Clock(), "enforce", "203.0.113.73")
    assert shadow.score == enforce.score
    assert shadow.action == enforce.action
    assert shadow.applied != enforce.applied
