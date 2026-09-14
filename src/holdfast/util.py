"""Shared helpers for the Holdfast daemon and CLI."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SOCK = "/tmp/holdfast.sock"
DEFAULT_HTTP_HOST = "0.0.0.0"
DEFAULT_HTTP_PORT = 47821
DECISION_TIMEOUT_S = 300
HTTP_BASE = "http://127.0.0.1:47821"


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def sock_path() -> str:
    return os.environ.get("HOLDFAST_SOCK") or DEFAULT_SOCK


def http_host() -> str:
    return os.environ.get("HOLDFAST_HTTP_HOST") or DEFAULT_HTTP_HOST


def http_port() -> int:
    return int(os.environ.get("HOLDFAST_HTTP_PORT") or DEFAULT_HTTP_PORT)


def decision_timeout() -> float:
    return float(os.environ.get("HOLDFAST_TIMEOUT") or DECISION_TIMEOUT_S)


def default_audit_path() -> Path:
    env = os.environ.get("HOLDFAST_AUDIT")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".local" / "share" / "holdfast" / "audit.jsonl"


def default_policy_path() -> Path:
    env = os.environ.get("HOLDFAST_POLICY")
    if env:
        return Path(env).expanduser()
    here = Path(__file__).resolve()
    candidates = [
        Path.cwd() / "policies" / "default.yaml",
        here.parents[2] / "policies" / "default.yaml",
        Path("/workspace/policies/default.yaml"),
        Path("/etc/holdfast/default.yaml"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def find_preload_lib() -> Path:
    candidates = [
        Path("/workspace/preload/libholdfast.so"),
        Path.cwd() / "preload" / "libholdfast.so",
        Path("/usr/local/lib/libholdfast.so"),
        Path(__file__).resolve().parents[2] / "preload" / "libholdfast.so",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return Path("/workspace/preload/libholdfast.so")


def find_jail_bin() -> Path:
    candidates = [
        Path("/workspace/jail/holdfast-jail"),
        Path.cwd() / "jail" / "holdfast-jail",
        Path("/usr/local/bin/holdfast-jail"),
        Path(__file__).resolve().parents[2] / "jail" / "holdfast-jail",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return Path("/workspace/jail/holdfast-jail")

