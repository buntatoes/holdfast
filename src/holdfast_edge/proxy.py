"""Minimal reverse proxy. Shadow mode always forwards. Enforce applies challenge/deny."""

from __future__ import annotations

from typing import Any

from holdfast_edge.config import EdgeConfig
from holdfast_edge.engine import EdgeEngine
from holdfast_edge.middleware import apply_status, request_from_scope


def build_proxy(
    origin: str,
    engine: EdgeEngine | None = None,
    config: EdgeConfig | None = None,
):
    import httpx
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse

    engine = engine or EdgeEngine(config)
    origin = origin.rstrip("/")
    app = FastAPI(title="Holdfast Edge Proxy", version="0.2.2")
    app.state.engine = engine
    app.state.origin = origin

    @app.get("/__holdfast_edge/health")
    def health() -> dict[str, Any]:
        return engine.health()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def catchall(request: Request, path: str) -> Response:
        try:
            payload = request_from_scope(request.scope)
            decision = engine.observe(payload)
        except Exception:
            decision = None
        if decision is not None:
            status = apply_status(decision.applied)
            if status is not None:
                return JSONResponse(decision.as_public(), status_code=status)
        url = f"{origin}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"
        body = await request.body()
        blocked = {"host", "content-length", "connection", "transfer-encoding"}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in blocked}
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            upstream = await client.request(
                request.method,
                url,
                content=body if body else None,
                headers=headers,
            )
        out_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=out_headers,
        )

    return app
