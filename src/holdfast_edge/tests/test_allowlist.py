from __future__ import annotations

from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def test_path_prefix_short_circuits_burst(clock: Clock) -> None:
    engine = make_engine(clock)
    last = None
    for _ in range(80):
        last = engine.observe(req("/health", src_ip="203.0.113.50", headers=BROWSER))
        clock.advance(0.01)
    assert last is not None
    assert last.allowlisted is True
    assert last.action == "allow"
    assert last.applied == "allow"
    assert last.score == 0
    assert last.rule_id == "edge.allowlist.path"


def test_cidr_allowlist(clock: Clock) -> None:
    engine = make_engine(
        clock,
        allowlist={"cidrs": ["198.51.100.0/24"], "path_prefixes": []},
    )
    last = None
    for i in range(50):
        last = engine.observe(req(f"/x{i}", src_ip="198.51.100.9", headers=BROWSER))
        clock.advance(0.01)
    assert last is not None
    assert last.allowlisted is True
    assert last.action == "allow"


def test_token_allowlist(clock: Clock) -> None:
    engine = make_engine(
        clock,
        allowlist={"header_tokens": ["op-secret"], "path_prefixes": []},
    )
    headers = dict(BROWSER)
    headers["x-holdfast-edge-token"] = "op-secret"
    last = None
    for i in range(50):
        last = engine.observe(req(f"/z{i}", src_ip="203.0.113.51", headers=headers))
        clock.advance(0.01)
    assert last.allowlisted is True
    assert last.action == "allow"


def test_wrong_token_is_scored(clock: Clock) -> None:
    engine = make_engine(
        clock,
        allowlist={"header_tokens": ["op-secret"], "path_prefixes": []},
    )
    headers = dict(BROWSER)
    headers["x-holdfast-edge-token"] = "nope"
    last = None
    for i in range(40):
        last = engine.observe(req("/", src_ip="203.0.113.52", headers=headers))
        clock.advance(0.05)
    assert last.allowlisted is False
    assert last.score >= 40


def test_static_assets_allowlisted(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/static/app.js", headers=BROWSER))
    assert d.rule_id == "edge.allowlist.path"


def test_health_prefix_does_not_match_healthcare(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/healthcare", headers=BROWSER))
    assert d.allowlisted is False
    assert d.rule_id != "edge.allowlist.path"


def test_health_child_still_allowlisted(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/health/live", headers=BROWSER))
    assert d.allowlisted is True
    assert d.rule_id == "edge.allowlist.path"


def test_dotdot_cannot_use_health_prefix(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/health/../admin", headers=BROWSER))
    assert d.allowlisted is False
    assert d.rule_id != "edge.allowlist.path"


def test_assets_dotdot_is_not_allowlisted(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/assets/../secret", headers=BROWSER))
    assert d.allowlisted is False
    assert d.rule_id != "edge.allowlist.path"


def test_encoded_dotdot_cannot_use_health_prefix(clock: Clock) -> None:
    """Percent-encoded .. must not ride a /health prefix allowlist."""
    engine = make_engine(clock)
    for path in (
        "/health/%2e%2e/admin",
        "/health/%2e%2e%2fadmin",
        "/health%2f%2e%2e%2fadmin",
        "/health/%2E%2E/admin",
        "/%68ealth/%2e%2e/admin",  # still collapses to /admin after decode+normalize
    ):
        d = engine.observe(req(path, headers=BROWSER))
        assert d.allowlisted is False, path
        assert d.rule_id != "edge.allowlist.path", path


def test_double_encoded_dotdot_cannot_use_health_prefix(clock: Clock) -> None:
    engine = make_engine(clock)
    for path in (
        "/health/%252e%252e/admin",
        "/health/%252e%252e%252fadmin",
        "/health/%25%32%65%25%32%65/admin",
    ):
        d = engine.observe(req(path, headers=BROWSER))
        assert d.allowlisted is False, path
        assert d.rule_id != "edge.allowlist.path", path


def test_encoded_health_child_still_allowlisted(clock: Clock) -> None:
    engine = make_engine(clock)
    d = engine.observe(req("/health/%6cive", headers=BROWSER))  # /health/live
    assert d.allowlisted is True
    assert d.rule_id == "edge.allowlist.path"


def test_observe_json_encoded_traversal_not_allowlisted(clock: Clock) -> None:
    """Observe API body path is normalized the same way as middleware paths."""
    engine = make_engine(clock, mode="shadow")
    from holdfast_edge.server import build_app
    from fastapi.testclient import TestClient

    client = TestClient(build_app(engine))
    body = client.post(
        "/v1/observe",
        json=req("/health/%2e%2e/admin", headers=BROWSER),
    ).json()
    assert body["decision"]["allowlisted"] is False
    assert body["decision"]["rule_id"] != "edge.allowlist.path"
