"""Allowlists run first. A match is always allow — never scored, never challenged."""

from __future__ import annotations

import hmac
import ipaddress
from dataclasses import dataclass
from typing import Any

from holdfast_edge.config import AllowlistConfig
from holdfast_edge.fingerprints import normalize_path


@dataclass(frozen=True)
class AllowHit:
    rule_id: str
    reason: str


def _in_cidr(src_ip: str | None, cidrs: tuple[str, ...]) -> str | None:
    if not src_ip or not cidrs:
        return None
    try:
        ip = ipaddress.ip_address(src_ip.split("%", 1)[0])
    except ValueError:
        return None
    for raw in cidrs:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if ip in net:
            return raw
    return None


def _token_ok(provided: str | None, allowed: tuple[str, ...]) -> bool:
    if not provided or not allowed:
        return False
    got = provided.encode("utf-8")
    for token in allowed:
        want = token.encode("utf-8")
        if hmac.compare_digest(got, want):
            return True
    return False


def _path_prefixed(path: str, prefix: str) -> bool:
    """Match the prefix or a child path. /health matches /health/live, not /healthcare."""
    if not prefix:
        return False
    path_n = normalize_path(path)
    pref = normalize_path(prefix)
    if pref == "/":
        return True
    if path_n == pref:
        return True
    return path_n.startswith(pref + "/")


def match(
    allow: AllowlistConfig,
    *,
    path: str,
    host: str | None = None,
    src_ip: str | None = None,
    client_fp: str | None = None,
    header_token: str | None = None,
) -> AllowHit | None:
    path_n = normalize_path(path or "/")
    for prefix in allow.path_prefixes:
        if prefix and _path_prefixed(path_n, prefix):
            return AllowHit("edge.allowlist.path", f"allowlisted path prefix {prefix}")
    if host:
        host_n = host.split(":", 1)[0].lower()
        for item in allow.hosts:
            if host_n == item.lower():
                return AllowHit("edge.allowlist.host", "allowlisted host")
    if client_fp and client_fp in set(allow.client_fps):
        return AllowHit("edge.allowlist.client", "allowlisted client fingerprint")
    cidr = _in_cidr(src_ip, allow.cidrs)
    if cidr:
        return AllowHit("edge.allowlist.cidr", "allowlisted network")
    if _token_ok(header_token, allow.header_tokens):
        return AllowHit("edge.allowlist.token", "allowlisted operator token")
    return None


def header_token_from(headers: Any, name: str) -> str | None:
    if not headers or not isinstance(headers, dict):
        return None
    want = name.lower()
    for key, value in headers.items():
        if str(key).lower() == want:
            return None if value is None else str(value)
    return None
