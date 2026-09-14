"""ASGI middleware. Fail-open on engine errors (false-positive DoS is the #1 risk)."""

from __future__ import annotations

from typing import Any

from holdfast_edge.engine import EdgeEngine, EdgeRequest

CHALLENGE_STATUS = 429
DENY_STATUS = 403


def request_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    headers = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers") or []}
    path = scope.get("path") or "/"
    qs = scope.get("query_string") or b""
    if qs:
        names = []
        for part in qs.decode("latin1", errors="replace").split("&"):
            if not part:
                continue
            names.append(part.split("=", 1)[0])
        query_names = names
    else:
        query_names = []
    client = (scope.get("client") or (None, None))[0]
    return {
        "method": scope.get("method") or "GET",
        "path": path,
        "host": headers.get("host"),
        "src_ip": client,
        "headers": headers,
        "query_param_names": query_names,
    }


def apply_status(applied: str) -> int | None:
    if applied == "challenge":
        return CHALLENGE_STATUS
    if applied == "deny":
        return DENY_STATUS
    return None


class EdgeMiddleware:
    """Starlette/FastAPI-compatible middleware. Does not import the host daemon."""

    def __init__(self, app: Any, engine: EdgeEngine | None = None):
        self.app = app
        self.engine = engine or EdgeEngine()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            payload = request_from_scope(scope)
            decision = self.engine.observe(payload)
        except Exception:
            await self.app(scope, receive, send)
            return
        status = apply_status(decision.applied)
        if status is None:
            await self.app(scope, receive, send)
            return
        body = decision.as_public()
        try:
            import json

            raw = json.dumps(body).encode("utf-8")
        except Exception:
            raw = b'{"error":"denied"}'
        headers = [
            (b"content-type", b"application/json"),
            (b"cache-control", b"no-store"),
            (b"x-holdfast-edge", decision.applied.encode("ascii")),
            (b"content-length", str(len(raw)).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": raw})
