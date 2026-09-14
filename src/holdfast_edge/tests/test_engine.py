from __future__ import annotations

import holdfast_edge
from holdfast_edge.middleware import apply_status, request_from_scope
from holdfast_edge.tests.conftest import BROWSER, Clock, make_engine, req


def test_package_does_not_import_host_daemon() -> None:
    import inspect
    import holdfast_edge as pkg
    import holdfast_edge.engine as engine
    import holdfast_edge.server as server
    import holdfast_edge.middleware as middleware

    for mod in (pkg, engine, server, middleware):
        src = inspect.getsource(mod)
        assert "from holdfast " not in src
        assert "import holdfast\n" not in src
        assert "from holdfast." not in src
        assert "import holdfast." not in src


def test_observe_api_roundtrip(clock: Clock) -> None:
    engine = make_engine(clock, mode="shadow")
    from holdfast_edge.server import build_app
    from fastapi.testclient import TestClient

    client = TestClient(build_app(engine))
    health = client.get("/health").json()
    assert health["ok"] is True
    assert health["package"] == "holdfast_edge"
    assert health["mode"] == "shadow"
    body = client.post("/v1/observe", json=req("/", headers=BROWSER)).json()
    assert body["decision"]["applied"] == "allow"
    assert "items" in client.get("/v1/provenance").json()


def test_middleware_shadow_never_blocks(clock: Clock) -> None:
    engine = make_engine(clock, mode="shadow")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from holdfast_edge.middleware import EdgeMiddleware

    inner = FastAPI()

    @inner.get("/{path:path}")
    def ok(path: str) -> dict:
        return {"ok": True, "path": path}

    app = EdgeMiddleware(inner, engine=engine)
    client = TestClient(app)
    for i in range(40):
        r = client.get(f"/p{i}", headers=BROWSER)
        assert r.status_code == 200
        clock.advance(0.05)


def test_middleware_enforce_challenges(clock: Clock) -> None:
    engine = make_engine(clock, mode="enforce")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from holdfast_edge.middleware import EdgeMiddleware

    inner = FastAPI()

    @inner.get("/")
    def ok() -> dict:
        return {"ok": True}

    app = EdgeMiddleware(inner, engine=engine)
    client = TestClient(app)
    last = None
    for _ in range(40):
        last = client.get("/", headers=BROWSER)
        clock.advance(0.05)
    assert last.status_code == 429
    assert last.json()["error"] == "challenge"
    assert "score" not in last.json()


def test_apply_status_mapping() -> None:
    assert apply_status("allow") is None
    assert apply_status("challenge") == 429
    assert apply_status("deny") == 403


def test_scope_parser_drops_query_values() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/search",
        "query_string": b"q=secret-name&page=1",
        "headers": [(b"host", b"example.test")],
        "client": ("203.0.113.1", 1234),
    }
    payload = request_from_scope(scope)
    assert payload["query_param_names"] == ["q", "page"]
    assert "secret-name" not in str(payload["query_param_names"])
