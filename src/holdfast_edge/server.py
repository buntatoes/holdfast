"""Observe API for operators and middleware callers. Binds 127.0.0.1:47831 by default.

Port is not 47821 so Edge cannot collide with the host daemon.
"""

from __future__ import annotations

from typing import Any

from holdfast_edge.config import EdgeConfig, load as load_config
from holdfast_edge.engine import EdgeEngine


def build_app(engine: EdgeEngine | None = None, config: EdgeConfig | None = None):
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    engine = engine or EdgeEngine(config or load_config())
    app = FastAPI(title="Holdfast Edge", version="0.2.1")
    app.state.engine = engine

    @app.get("/health")
    def health() -> dict[str, Any]:
        return engine.health()

    @app.get("/v1/config")
    def config_view() -> dict[str, Any]:
        cfg = engine.config
        return {
            "mode": cfg.mode,
            "thresholds": {
                "challenge": cfg.thresholds.challenge,
                "deny": cfg.thresholds.deny,
                "min_observations_before_deny": cfg.thresholds.min_observations_before_deny,
                "min_window_s_before_deny": cfg.thresholds.min_window_s_before_deny,
            },
            "windows": {
                "burst_s": cfg.windows.burst_s,
                "fanout_s": cfg.windows.fanout_s,
                "retry_s": cfg.windows.retry_s,
                "goal_s": cfg.windows.goal_s,
            },
            "source": cfg.source,
        }

    @app.post("/v1/observe")
    def observe(body: dict[str, Any]) -> dict[str, Any]:
        decision = engine.observe(body)
        return {"decision": decision.as_operator(), "public": decision.as_public()}

    @app.get("/v1/provenance")
    def provenance(limit: int = 100) -> dict[str, Any]:
        return {"items": engine.provenance.tail(limit)}

    @app.middleware("http")
    async def fail_closed_health_only(request: Request, call_next):
        return await call_next(request)

    @app.exception_handler(Exception)
    async def fail_open(_request: Request, _exc: Exception):
        return JSONResponse(
            {"decision": {"action": "allow", "applied": "allow", "rule_id": "edge.fail_open"}},
            status_code=200,
        )

    return app


def main() -> None:
    import uvicorn

    engine = EdgeEngine(load_config())
    app = build_app(engine)
    uvicorn.run(
        app,
        host=engine.config.listen_host,
        port=engine.config.listen_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
