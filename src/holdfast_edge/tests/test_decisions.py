from __future__ import annotations

from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def test_uncertain_is_challenge_not_deny(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for _ in range(40):
        last = engine.observe(req("/", src_ip="203.0.113.60", headers=BROWSER))
        clock.advance(0.05)
    assert last is not None
    assert 40 <= last.score < 80
    assert last.action == "challenge"
    assert last.action != "deny"


def test_first_hit_never_denies(clock: Clock) -> None:
    engine = make_engine(
        clock,
        thresholds={
            "challenge": 40,
            "deny": 50,
            "min_observations_before_deny": 100,
            "min_window_s_before_deny": 5,
        },
        signals={"burst": {"requests": 2}},
    )
    d1 = engine.observe(req("/", src_ip="203.0.113.61", headers=BROWSER))
    clock.advance(0.01)
    d2 = engine.observe(req("/", src_ip="203.0.113.61", headers=BROWSER))
    clock.advance(0.01)
    d3 = engine.observe(req("/", src_ip="203.0.113.61", headers=BROWSER))
    assert d3.score >= 50
    assert d3.action == "challenge"
    assert "first-hit" in d3.reason
    assert d1.action != "deny"


def test_deny_after_rails_clear(clock: Clock) -> None:
    engine = make_engine(
        clock,
        thresholds={
            "challenge": 40,
            "deny": 80,
            "min_observations_before_deny": 3,
            "min_window_s_before_deny": 1,
        },
        signals={"burst": {"requests": 10}},
    )
    last = None
    for _ in range(30):
        last = engine.observe(req("/", src_ip="203.0.113.62", headers=BROWSER))
        clock.advance(0.1)
    assert last is not None
    assert last.score >= 80
    assert last.observations >= 3
    assert last.action == "deny"
    assert last.rule_id == "edge.burst"
    assert last.reason
    assert last.observed_at


def test_short_window_downgrades_deny(clock: Clock) -> None:
    engine = make_engine(
        clock,
        thresholds={
            "challenge": 10,
            "deny": 20,
            "min_observations_before_deny": 2,
            "min_window_s_before_deny": 30,
        },
        signals={"burst": {"requests": 2}},
    )
    engine.observe(req("/", src_ip="203.0.113.63", headers=BROWSER))
    clock.advance(0.2)
    d = engine.observe(req("/", src_ip="203.0.113.63", headers=BROWSER))
    clock.advance(0.2)
    d = engine.observe(req("/", src_ip="203.0.113.63", headers=BROWSER))
    assert d.action == "challenge"
    assert "short window" in d.reason
