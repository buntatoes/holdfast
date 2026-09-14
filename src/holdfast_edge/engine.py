"""Edge engine: allowlist → fingerprint → score → decide → provenance.

Must not import the host `holdfast` daemon package.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from holdfast_edge.allowlist import header_token_from, match as allow_match
from holdfast_edge.config import EdgeConfig, default_config
from holdfast_edge.decisions import Decision, decide
from holdfast_edge.fingerprints import (
    client_fingerprint,
    extract_ids,
    header_names_of,
    normalize_path,
    path_fingerprint,
    redact_path,
)
from holdfast_edge.provenance import ProvenanceLog
from holdfast_edge.scoring import noisy_or
from holdfast_edge.signals import compute as compute_signals
from holdfast_edge.store import WindowStore


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class EdgeRequest:
    __slots__ = (
        "method",
        "path",
        "host",
        "src_ip",
        "user_agent",
        "client_fp",
        "headers",
        "header_names",
        "header_token",
        "status",
        "query_param_names",
    )

    def __init__(
        self,
        *,
        method: str = "GET",
        path: str = "/",
        host: str | None = None,
        src_ip: str | None = None,
        user_agent: str | None = None,
        client_fp: str | None = None,
        headers: dict[str, str] | None = None,
        header_names: list[str] | None = None,
        header_token: str | None = None,
        status: int | None = None,
        query_param_names: list[str] | None = None,
    ):
        self.method = (method or "GET").upper()
        self.path = path or "/"
        self.host = host
        self.src_ip = src_ip
        self.user_agent = user_agent
        self.client_fp = client_fp
        self.headers = headers or {}
        names = header_names if header_names is not None else list(header_names_of(self.headers))
        self.header_names = tuple(n.lower() for n in names)
        self.header_token = header_token
        self.status = status
        self.query_param_names = tuple(query_param_names or ())

    @classmethod
    def from_any(cls, data: EdgeRequest | dict[str, Any]) -> EdgeRequest:
        if isinstance(data, EdgeRequest):
            return data
        headers = dict(data.get("headers") or {})
        ua = data.get("user_agent")
        if ua is None and headers:
            for key, value in headers.items():
                if str(key).lower() == "user-agent":
                    ua = value
                    break
        token = data.get("header_token")
        if token is None:
            token = header_token_from(headers, str(data.get("header_token_name") or "x-holdfast-edge-token"))
        host = data.get("host")
        if host is None and headers:
            host = headers.get("host") or headers.get("Host")
        return cls(
            method=str(data.get("method") or "GET"),
            path=str(data.get("path") or "/"),
            host=None if host is None else str(host),
            src_ip=None if data.get("src_ip") is None else str(data.get("src_ip")),
            user_agent=None if ua is None else str(ua),
            client_fp=None if data.get("client_fp") is None else str(data.get("client_fp")),
            headers=headers,
            header_names=list(data.get("header_names") or []) or None,
            header_token=None if token is None else str(token),
            status=data.get("status"),
            query_param_names=list(data.get("query_param_names") or []),
        )


class EdgeEngine:
    def __init__(
        self,
        config: EdgeConfig | None = None,
        *,
        now: Callable[[], float] | None = None,
    ):
        self.config = config or default_config()
        self._now = now
        self.store = WindowStore(self.config.windows)
        self.provenance = ProvenanceLog(
            retention_hours=self.config.retention_hours,
            path=self.config.provenance_path,
            now=self._now,
        )

    def _epoch(self) -> float:
        if self._now is not None:
            return float(self._now())
        import time

        return time.time()

    def observe(self, request: EdgeRequest | dict[str, Any]) -> Decision:
        cfg = self.config
        now = self._epoch()
        observed_at = _iso(now)
        req = EdgeRequest.from_any(request)
        req.path = normalize_path(req.path)

        token_name = cfg.allowlist.header_token_name
        token = req.header_token or header_token_from(req.headers, token_name)
        client_fp = client_fingerprint(
            src_ip=req.src_ip,
            user_agent=req.user_agent,
            client_fp=req.client_fp,
            salt=cfg.salt,
        )
        hit = allow_match(
            cfg.allowlist,
            path=req.path,
            host=req.host,
            src_ip=req.src_ip,
            client_fp=client_fp,
            header_token=token,
        )
        template = redact_path(req.path)
        path_fp = path_fingerprint(req.path, salt=cfg.salt)

        req.src_ip = None
        req.user_agent = None
        req.client_fp = None

        if hit:
            decision = Decision(
                action="allow",
                applied="allow",
                score=0.0,
                rule_id=hit.rule_id,
                reason=hit.reason,
                observed_at=observed_at,
                client_fp=client_fp,
                path_fp=path_fp,
                signals={},
                observations=0,
                mode=cfg.mode,
                allowlisted=True,
            )
            self.provenance.append(decision)
            return decision

        snap = self.store.record(
            client_fp,
            template,
            req.method,
            now,
            status=req.status,
            header_names=req.header_names,
            id_keys=extract_ids(req.path),
        )
        signals = compute_signals(snap, cfg)
        score = noisy_or(signals, cfg)
        decision = decide(
            score=score,
            signals=signals,
            snap=snap,
            cfg=cfg,
            now=now,
            observed_at=observed_at,
            path_fp=path_fp,
        )
        self.provenance.append(decision)
        return decision

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "package": "holdfast_edge",
            "mode": self.config.mode,
            "version": "0.2.1",
            "listen": f"{self.config.listen_host}:{self.config.listen_port}",
            "thresholds": {
                "challenge": self.config.thresholds.challenge,
                "deny": self.config.thresholds.deny,
                "min_observations_before_deny": self.config.thresholds.min_observations_before_deny,
            },
        }
