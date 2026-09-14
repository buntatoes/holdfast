from __future__ import annotations

from holdfast_edge.provenance import REQUIRED_DENY_FIELDS, record_from_decision
from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def test_deny_has_required_fields(clock: Clock) -> None:
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
        last = engine.observe(req("/", src_ip="203.0.113.90", headers=BROWSER))
        clock.advance(0.1)
    assert last.action == "deny"
    rec = record_from_decision(last)
    for key in REQUIRED_DENY_FIELDS:
        assert rec[key] not in (None, "")
    items = engine.provenance.tail(10)
    assert items[-1]["rule_id"] == last.rule_id
    assert items[-1]["score"] == last.score


def test_no_pii_in_provenance(clock: Clock) -> None:
    engine = make_engine(clock)
    engine.observe(
        req(
            "/users/alice@example.com/12345",
            src_ip="192.0.2.9",
            user_agent="Mozilla/5.0 secret-token",
            headers={**BROWSER, "user-agent": "Mozilla/5.0 secret-token"},
        )
    )
    rec = engine.provenance.tail(1)[0]
    blob = str(rec)
    assert "alice@example.com" not in blob
    assert "192.0.2.9" not in blob
    assert "secret-token" not in blob
    assert rec["client_fp"]
    assert rec["path_fp"]
    assert rec["client_fp"] != "192.0.2.9"


def test_retention_prunes(clock: Clock) -> None:
    engine = make_engine(clock, retention_hours=1 / 3600)
    engine.observe(req("/", src_ip="203.0.113.91", headers=BROWSER))
    assert len(engine.provenance.tail(10)) == 1
    clock.advance(5)
    engine.observe(req("/", src_ip="203.0.113.91", headers=BROWSER))
    items = engine.provenance.tail(10)
    assert len(items) == 1


def test_supplied_client_fp_is_hashed(clock: Clock) -> None:
    engine = make_engine(clock)
    raw_ip = "203.0.113.10"
    engine.observe(req("/", src_ip=raw_ip, client_fp=raw_ip, headers=BROWSER))
    rec = engine.provenance.tail(1)[0]
    assert rec["client_fp"] != raw_ip
    assert raw_ip not in str(rec)
    assert rec["client_fp"]
