"""Hash fingerprints and redact paths. Raw IPs, UAs, and bodies never stored."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_LONG_HEX = re.compile(r"[0-9a-fA-F]{16,}")
_NUM_SEG = re.compile(r"/(\d+)(?=/|$)")
_QUERY = re.compile(r"\?.*$")


def sha16(*parts: str, salt: str = "") -> str:
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    for part in parts:
        h.update(b"\x1f")
        h.update((part or "").encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]


def normalize_path(path: str) -> str:
    """Resolve . and .. so allowlists and scores see the real path. Never walk above /."""
    raw = (path or "/").split("#", 1)[0].split("?", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw
    parts: list[str] = []
    for seg in raw.split("/"):
        if seg in {"", "."}:
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts) if parts else "/"


def client_fingerprint(
    *,
    src_ip: str | None = None,
    user_agent: str | None = None,
    client_fp: str | None = None,
    salt: str = "",
) -> str:
    """Stable client id. Always hashed — a caller-supplied value is never stored raw."""
    if client_fp:
        return sha16(str(client_fp), salt=salt)
    return sha16(src_ip or "", user_agent or "", salt=salt)


def path_fingerprint(path: str, salt: str = "") -> str:
    return sha16(redact_path(path), salt=salt)


def redact_path(path: str) -> str:
    """Keep a routing pattern. Drop identifiers that look like people or secrets."""
    raw = (path or "/").split("#", 1)[0]
    raw = _QUERY.sub("", raw)
    if not raw.startswith("/"):
        raw = "/" + raw
    raw = _EMAIL.sub(":email", raw)
    raw = _UUID.sub(":id", raw)
    raw = _LONG_HEX.sub(":id", raw)
    raw = _NUM_SEG.sub("/:id", raw)
    return raw[:256]


def header_names_of(headers: Any) -> tuple[str, ...]:
    if not headers:
        return ()
    if isinstance(headers, dict):
        return tuple(sorted({str(k).lower() for k in headers}))
    return tuple(sorted({str(x).lower() for x in headers if x}))


def extract_ids(path: str) -> tuple[str, ...]:
    """Numeric and UUID path segments from the raw path (in-memory scoring only)."""
    raw = (path or "/").split("#", 1)[0]
    raw = _QUERY.sub("", raw)
    found: list[str] = []
    found.extend(m.group(0).lower() for m in _UUID.finditer(raw))
    found.extend(_NUM_SEG.findall(raw))
    return tuple(found)
