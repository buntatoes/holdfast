"""First-match-wins policy engine with an in-memory session overlay."""

from __future__ import annotations

import fnmatch
import os
import re
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

Action = Literal["allow", "deny", "ask"]


class Match(BaseModel):
    """A rule's match clause. Unspecified fields are wildcards."""

    model_config = ConfigDict(extra="allow")

    kind: str | None = None
    op: str | None = None
    path: str | None = None
    path_glob: str | None = None
    path_prefix: str | None = None
    host: str | None = None
    port: int | str | None = None
    argv_contains: str | list[str] | None = None
    flags: str | None = None
    under_cwd: bool = False
    family: str | None = None
    session: str | None = None
    exact_path: str | None = None
    argv: list[str] | None = None


class Rule(BaseModel):
    id: str
    match: Match = Field(default_factory=Match)
    action: Action
    session: str | None = None


@dataclass(frozen=True)
class Verdict:
    action: Action
    rule_id: str | None
    actor: str

    @property
    def allow(self) -> bool:
        return self.action == "allow"

    @property
    def deny(self) -> bool:
        return self.action == "deny"

    @property
    def ask(self) -> bool:
        return self.action == "ask"


def norm_path(path: str, cwd: str | None = None) -> str:
    expanded = os.path.expanduser(str(path))
    if cwd and not os.path.isabs(expanded):
        expanded = os.path.join(os.path.expanduser(str(cwd)), expanded)
    return os.path.normpath(os.path.abspath(expanded))


def is_under(path: str, root: str, cwd: str | None = None) -> bool:
    child = norm_path(path, cwd)
    parent = norm_path(root, cwd)
    if child == parent:
        return True
    prefix = parent if parent.endswith(os.sep) else parent + os.sep
    return child.startswith(prefix)


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    compiled = re.compile("^" + "".join(out) + "$")
    _GLOB_CACHE[pattern] = compiled
    return compiled


def glob_match(path: str, pattern: str) -> bool:
    path_u = path.replace("\\", "/")
    pat = os.path.expanduser(pattern).replace("\\", "/")
    if path_u == pat:
        return True
    if fnmatch.fnmatch(path_u, pat):
        return True
    if glob_to_regex(pat).match(path_u):
        return True
    try:
        if PurePosixPath(path_u).match(pat):
            return True
        stripped = pat[1:] if pat.startswith("/") else pat
        rel = path_u[1:] if path_u.startswith("/") else path_u
        if PurePosixPath(rel).match(stripped):
            return True
    except (ValueError, OSError):
        pass
    if pat.endswith("/**"):
        return is_under(path_u, pat[:-3])
    return False


def _as_port(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _detail(request: dict[str, Any]) -> dict[str, Any]:
    detail = request.get("detail") or {}
    return detail if isinstance(detail, dict) else {}


def candidate_paths(request: dict[str, Any]) -> list[str]:
    detail = _detail(request)
    cwd = request.get("cwd")
    found: list[str] = []

    def add(raw: str) -> None:
        if not raw:
            return
        unix = raw.replace("\\", "/")
        found.append(unix)
        stripped = unix[5:] if unix.startswith("unix:") else unix
        if stripped.startswith("unix:@"):
            found.append(stripped)
            return
        if stripped.startswith("/"):
            found.append(norm_path(stripped, cwd))
        elif not unix.startswith("unix:"):
            found.append(norm_path(unix, cwd))

    if detail.get("path"):
        add(str(detail["path"]))
    host = detail.get("host")
    family = str(detail.get("family") or "").lower()
    if host and (
        family in {"unix", "local", "af_unix"}
        or "/" in str(host)
        or str(host).startswith("unix:")
    ):
        add(str(host))
    out: list[str] = []
    seen: set[str] = set()
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def matches(rule: Rule, request: dict[str, Any]) -> bool:
    m = rule.match
    session = request.get("session")
    if rule.session and rule.session != session:
        return False
    if m.session and m.session != session:
        return False
    if m.kind and m.kind != request.get("kind"):
        return False
    if m.op and m.op != request.get("op"):
        return False

    detail = _detail(request)
    cwd = request.get("cwd")

    if m.flags is not None and str(detail.get("flags") or "") != str(m.flags):
        return False

    if m.family is not None:
        if str(detail.get("family") or "").lower() != str(m.family).lower():
            return False

    if m.host is not None:
        got = str(detail.get("host") or "")
        want = str(m.host)
        if got.lower() != want.lower() and not glob_match(got, want):
            return False

    if m.port is not None:
        if _as_port(detail.get("port")) != _as_port(m.port):
            return False

    if m.under_cwd:
        path = detail.get("path")
        if not path or not cwd or not is_under(str(path), str(cwd), cwd):
            return False

    if m.exact_path is not None:
        path = detail.get("path")
        if not path or norm_path(str(path), cwd) != m.exact_path:
            return False

    pattern = m.path_glob or m.path
    if pattern is not None:
        paths = candidate_paths(request)
        if not paths or not any(glob_match(p, pattern) for p in paths):
            # also try the raw (non-normalized) path for globs like **/.ssh/**
            raws = []
            if detail.get("path"):
                raws.append(str(detail["path"]).replace("\\", "/"))
            if detail.get("host") and "/" in str(detail.get("host")):
                raws.append(str(detail["host"]).replace("\\", "/"))
            if not any(glob_match(p, pattern) for p in raws + paths):
                return False

    if m.path_prefix is not None:
        paths = candidate_paths(request)
        if not paths or not any(is_under(p, m.path_prefix, cwd) for p in paths):
            return False

    if m.argv is not None:
        got_argv = [str(x) for x in (detail.get("argv") or [])]
        if got_argv != [str(x) for x in m.argv]:
            return False

    if m.argv_contains is not None:
        argv = [str(x) for x in (detail.get("argv") or [])]
        needles: Iterable[str]
        if isinstance(m.argv_contains, list):
            needles = [str(x) for x in m.argv_contains]
        else:
            needles = [str(m.argv_contains)]
        blob = "\x00".join(argv)
        for needle in needles:
            if needle in argv:
                continue
            if any(needle in item for item in argv):
                continue
            if needle in blob:
                continue
            return False

    return True


class PolicyEngine:
    """File-backed rules plus a process-session overlay (first match wins)."""

    def __init__(self, rules: list[Rule], source: str | None = None):
        self.rules = list(rules)
        self.overlay: list[Rule] = []
        self.source = source
        self._lock = threading.Lock()

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> PolicyEngine:
        raw_rules = data.get("rules") or []
        rules = [Rule.model_validate(item) for item in raw_rules]
        return cls(rules, source=source)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        path = Path(path)
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError(f"policy file {path} must be a YAML mapping")
        return cls.from_dict(data, source=str(path))

    def all_rules(self) -> list[Rule]:
        with self._lock:
            return list(self.overlay) + list(self.rules)

    def evaluate(self, request: dict[str, Any]) -> Verdict:
        for rule in self.all_rules():
            if matches(rule, request):
                return Verdict(rule.action, rule.id, f"policy:{rule.id}")
        return Verdict("deny", None, "fail-closed")

    def remember_session(self, request: dict[str, Any], action: Action) -> Rule:
        """Insert a session-scoped rule at the front of the overlay."""
        detail = _detail(request)
        cwd = request.get("cwd")
        match_data: dict[str, Any] = {
            "kind": request.get("kind"),
            "op": request.get("op"),
        }
        path = detail.get("path")
        if path:
            match_data["exact_path"] = norm_path(str(path), cwd)
        flags = detail.get("flags")
        if flags is not None:
            match_data["flags"] = flags
        host = detail.get("host")
        if host is not None:
            match_data["host"] = host
        if detail.get("port") is not None:
            match_data["port"] = detail.get("port")
        family = detail.get("family")
        if family is not None:
            match_data["family"] = family
        argv = detail.get("argv")
        if argv is not None:
            match_data["argv"] = list(argv)
        rule = Rule(
            id=f"session-{uuid.uuid4().hex[:12]}",
            match=Match.model_validate(match_data),
            action=action,
            session=request.get("session"),
        )
        with self._lock:
            self.overlay.insert(0, rule)
        return rule

    def summary(self) -> dict[str, Any]:
        def dump(rule: Rule) -> dict[str, Any]:
            item = {
                "id": rule.id,
                "action": rule.action,
                "match": rule.match.model_dump(exclude_none=True),
            }
            if rule.session:
                item["session"] = rule.session
            return item

        with self._lock:
            overlay = [dump(r) for r in self.overlay]
            rules = [dump(r) for r in self.rules]
        return {
            "source": self.source,
            "rule_count": len(rules),
            "overlay_count": len(overlay),
            "rules": rules,
            "overlay": overlay,
        }
