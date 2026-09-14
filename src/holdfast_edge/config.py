"""Tunable Edge thresholds. Defaults are conservative: shadow, challenge-first."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

Mode = Literal["shadow", "enforce"]


def _as_mode(value: Any) -> Mode:
    raw = str(value or "shadow").strip().lower().replace("-", "_")
    if raw in {"enforce", "live", "on"}:
        return "enforce"
    return "shadow"


@dataclass(frozen=True)
class Thresholds:
    """Score bars. Deny only when score and observation count both clear."""

    challenge: float = 40.0
    deny: float = 80.0
    min_observations_before_deny: int = 3
    min_window_s_before_deny: float = 5.0


@dataclass(frozen=True)
class Windows:
    burst_s: float = 10.0
    fanout_s: float = 30.0
    retry_s: float = 20.0
    goal_s: float = 60.0


@dataclass(frozen=True)
class SignalBars:
    """Raw counts that map to a mid-band score of 50 for that signal."""

    burst_requests: int = 40
    fanout_distinct_paths: int = 15
    retry_repeats: int = 8
    goal_sequence_hits: int = 6
    goal_sensitive_families: int = 4
    tool_client_max: float = 25.0


@dataclass(frozen=True)
class Weights:
    """Noisy-OR weights for behavior signals. Tool-shape is corroboration only."""

    burst: float = 1.0
    fanout: float = 1.0
    retry_loop: float = 1.0
    goal_loop: float = 1.0
    tool_client: float = 0.0  # not in the OR; added as a small bonus separately


@dataclass(frozen=True)
class AllowlistConfig:
    path_prefixes: tuple[str, ...] = ("/health", "/assets/", "/static/")
    hosts: tuple[str, ...] = ()
    client_fps: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    header_tokens: tuple[str, ...] = ()
    header_token_name: str = "x-holdfast-edge-token"


@dataclass(frozen=True)
class EdgeConfig:
    """Full Edge configuration. Default mode is shadow (log only)."""

    version: int = 1
    mode: Mode = "shadow"
    salt: str = ""
    retention_hours: float = 24.0
    provenance_path: str | None = None
    listen_host: str = "127.0.0.1"
    listen_port: int = 47831
    thresholds: Thresholds = field(default_factory=Thresholds)
    windows: Windows = field(default_factory=Windows)
    bars: SignalBars = field(default_factory=SignalBars)
    weights: Weights = field(default_factory=Weights)
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)
    source: str | None = None

    def is_shadow(self) -> bool:
        return self.mode != "enforce"

    def with_mode(self, mode: str) -> EdgeConfig:
        return replace(self, mode=_as_mode(mode))


def _tuple_str(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(x) for x in value)


def from_dict(data: dict[str, Any], source: str | None = None) -> EdgeConfig:
    data = data or {}
    th = data.get("thresholds") or {}
    win = data.get("windows") or {}
    sig = data.get("signals") or {}
    weights = data.get("weights") or {}
    allow = data.get("allowlist") or {}
    burst = sig.get("burst") or {}
    fanout = sig.get("fanout") or {}
    retry = sig.get("retry_loop") or {}
    goal = sig.get("goal_loop") or {}
    tool = sig.get("tool_client") or {}
    mode = _as_mode(os.environ.get("HOLDFAST_EDGE_MODE") or data.get("mode") or "shadow")
    salt = os.environ.get("HOLDFAST_EDGE_SALT") or str(data.get("salt") or "")
    port = int(os.environ.get("HOLDFAST_EDGE_HTTP_PORT") or data.get("listen_port") or 47831)
    host = os.environ.get("HOLDFAST_EDGE_HTTP_HOST") or str(data.get("listen_host") or "127.0.0.1")
    return EdgeConfig(
        version=int(data.get("version") or 1),
        mode=mode,
        salt=salt,
        retention_hours=float(data.get("retention_hours") or 24.0),
        provenance_path=data.get("provenance_path"),
        listen_host=str(host),
        listen_port=port,
        thresholds=Thresholds(
            challenge=float(th.get("challenge", 40.0)),
            deny=float(th.get("deny", 80.0)),
            min_observations_before_deny=int(th.get("min_observations_before_deny", 3)),
            min_window_s_before_deny=float(th.get("min_window_s_before_deny", 5.0)),
        ),
        windows=Windows(
            burst_s=float(win.get("burst_s", 10.0)),
            fanout_s=float(win.get("fanout_s", 30.0)),
            retry_s=float(win.get("retry_s", 20.0)),
            goal_s=float(win.get("goal_s", 60.0)),
        ),
        bars=SignalBars(
            burst_requests=int(burst.get("requests", 40)),
            fanout_distinct_paths=int(fanout.get("distinct_paths", 15)),
            retry_repeats=int(retry.get("repeats", 8)),
            goal_sequence_hits=int(goal.get("sequence_hits", 6)),
            goal_sensitive_families=int(goal.get("sensitive_families", 4)),
            tool_client_max=float(tool.get("max_score", 25.0)),
        ),
        weights=Weights(
            burst=float(weights.get("burst", 1.0)),
            fanout=float(weights.get("fanout", 1.0)),
            retry_loop=float(weights.get("retry_loop", 1.0)),
            goal_loop=float(weights.get("goal_loop", 1.0)),
            tool_client=float(weights.get("tool_client", 0.0)),
        ),
        allowlist=AllowlistConfig(
            path_prefixes=_tuple_str(
                allow["path_prefixes"]
                if "path_prefixes" in allow
                else ("/health", "/assets/", "/static/")
            ),
            hosts=_tuple_str(allow.get("hosts")),
            client_fps=_tuple_str(allow.get("client_fps")),
            cidrs=_tuple_str(allow.get("cidrs")),
            header_tokens=_tuple_str(allow.get("header_tokens")),
            header_token_name=str(allow.get("header_token_name") or "x-holdfast-edge-token"),
        ),
        source=source,
    )


def default_config() -> EdgeConfig:
    return from_dict({})


def load_yaml(path: str | Path) -> EdgeConfig:
    import yaml

    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"edge policy {path} must be a YAML mapping")
    return from_dict(data, source=str(path))


def default_policy_path() -> Path:
    env = os.environ.get("HOLDFAST_EDGE_POLICY")
    if env:
        return Path(env).expanduser()
    here = Path(__file__).resolve()
    candidates = [
        Path.cwd() / "policies" / "edge.yaml",
        here.parents[2] / "policies" / "edge.yaml",
        Path("/etc/holdfast/edge.yaml"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def load() -> EdgeConfig:
    path = default_policy_path()
    if path.is_file():
        return load_yaml(path)
    return default_config()
