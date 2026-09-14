from __future__ import annotations

import os
from pathlib import Path

import pytest

from holdfast.policy import PolicyEngine, Verdict, glob_match, is_under, norm_path
from holdfast.server import is_quiet_allow

DEFAULT_YAML = Path("/workspace/policies/default.yaml")
if not DEFAULT_YAML.is_file():
    DEFAULT_YAML = Path(__file__).resolve().parents[3] / "policies" / "default.yaml"


CWD = "/workspace"


def _req(
    kind: str,
    op: str,
    *,
    path: str | None = None,
    flags: str | None = None,
    host: str | None = None,
    port: int | None = None,
    argv: list[str] | None = None,
    cwd: str = CWD,
    session: str = "sess-1",
    family: str | None = None,
) -> dict:
    detail: dict = {}
    if path is not None:
        detail["path"] = path
    if flags is not None:
        detail["flags"] = flags
    if host is not None:
        detail["host"] = host
    if port is not None:
        detail["port"] = port
    if argv is not None:
        detail["argv"] = argv
    if family is not None:
        detail["family"] = family
    return {
        "id": "req-1",
        "session": session,
        "kind": kind,
        "op": op,
        "pid": 100,
        "cwd": cwd,
        "exe": "/usr/bin/python3",
        "detail": detail,
    }


@pytest.fixture
def shipped() -> PolicyEngine:
    assert DEFAULT_YAML.is_file(), f"missing shipped policy {DEFAULT_YAML}"
    return PolicyEngine.from_yaml(DEFAULT_YAML)


def test_cwd_read_allowed(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "open", path=f"{CWD}/demo/brief.txt", flags="r"))
    assert v.action == "allow"
    assert v.rule_id == "allow-cwd-read"
    assert v.actor == "policy:allow-cwd-read"


def test_cwd_relative_read_allowed(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "open", path="demo/brief.txt", flags="r"))
    assert v.action == "allow"


def test_ordinary_system_read_allowed(shipped: PolicyEngine) -> None:
    passwd = shipped.evaluate(_req("file", "open", path="/etc/passwd", flags="r"))
    assert passwd.action == "allow"
    assert passwd.rule_id == "allow-file-read"
    stdlib = shipped.evaluate(
        _req("file", "open", path="/usr/lib/python3.12/os.py", flags="r")
    )
    assert stdlib.action == "allow"


def test_shadow_denied(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "open", path="/etc/shadow", flags="r"))
    assert v.action == "deny"
    assert v.rule_id == "deny-etc-shadow"


def test_root_denied(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "open", path="/root/.bashrc", flags="r"))
    assert v.action == "deny"
    assert v.rule_id == "deny-root"


def test_ssh_keys_denied(shipped: PolicyEngine) -> None:
    home_ssh = os.path.expanduser("~/.ssh/id_ed25519")
    v = shipped.evaluate(_req("file", "open", path=home_ssh, flags="r"))
    assert v.action == "deny"
    other = shipped.evaluate(
        _req("file", "open", path="/home/other/.ssh/id_rsa", flags="r")
    )
    assert other.action == "deny"


def test_aws_and_gnupg_denied(shipped: PolicyEngine) -> None:
    aws = shipped.evaluate(
        _req("file", "open", path=os.path.expanduser("~/.aws/credentials"), flags="r")
    )
    gpg = shipped.evaluate(
        _req("file", "open", path=os.path.expanduser("~/.gnupg/secring.gpg"), flags="r")
    )
    assert aws.action == "deny"
    assert gpg.action == "deny"


def test_file_write_asks(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "open", path=f"{CWD}/demo/out.txt", flags="w"))
    assert v.action == "ask"
    assert v.rule_id == "ask-file-write"


def test_unlink_asks(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(_req("file", "unlink", path=f"{CWD}/demo/out.txt"))
    assert v.action == "ask"


def test_exec_asks(shipped: PolicyEngine) -> None:
    v = shipped.evaluate(
        _req("shell", "exec", argv=["curl", "https://evil.example"], path="/usr/bin/curl")
    )
    assert v.action == "ask"


def test_connect_asks_except_holdfast(shipped: PolicyEngine) -> None:
    ask = shipped.evaluate(
        _req("net", "connect", host="1.1.1.1", port=443, family="tcp")
    )
    assert ask.action == "ask"
    allow = shipped.evaluate(
        _req("net", "connect", host="127.0.0.1", port=47821, family="tcp")
    )
    assert allow.action == "allow"
    assert allow.rule_id == "allow-holdfast-http-loopback"
    unix = shipped.evaluate(
        _req("net", "connect", host="/tmp/holdfast.sock", family="unix", path="/tmp/holdfast.sock")
    )
    assert unix.action == "allow"
    unix_prefixed = shipped.evaluate(
        _req("net", "connect", host="unix:/tmp/holdfast.sock", family="unix")
    )
    assert unix_prefixed.action == "allow"


def test_first_match_wins() -> None:
    engine = PolicyEngine.from_dict(
        {
            "rules": [
                {
                    "id": "deny-tmp",
                    "match": {"kind": "file", "path_prefix": "/tmp"},
                    "action": "deny",
                },
                {
                    "id": "allow-tmp",
                    "match": {"kind": "file", "path_prefix": "/tmp"},
                    "action": "allow",
                },
            ]
        }
    )
    v = engine.evaluate(_req("file", "open", path="/tmp/x", flags="w"))
    assert v.rule_id == "deny-tmp"
    assert v.action == "deny"


def test_remember_session_overlay(shipped: PolicyEngine) -> None:
    req = _req("file", "open", path=f"{CWD}/demo/out.txt", flags="w", session="abc")
    assert shipped.evaluate(req).action == "ask"
    rule = shipped.remember_session(req, "allow")
    assert rule.session == "abc"
    assert shipped.evaluate(req).action == "allow"
    assert shipped.evaluate(req).rule_id == rule.id
    other_session = dict(req)
    other_session["session"] = "zzz"
    assert shipped.evaluate(other_session).action == "ask"


def test_glob_and_under_helpers() -> None:
    assert glob_match("/home/u/.ssh/id_rsa", "**/.ssh/**")
    assert glob_match("/tmp/holdfast.sock", "**/holdfast.sock")
    assert is_under("/workspace/demo/a", "/workspace")
    assert not is_under("/workspace-other/x", "/workspace")
    assert norm_path("demo/x", cwd="/workspace") == "/workspace/demo/x"


def test_quiet_allow_only_policy_file_reads(shipped: PolicyEngine) -> None:
    read = _req("file", "open", path=f"{CWD}/demo/brief.txt", flags="r")
    assert is_quiet_allow(read, shipped.evaluate(read))
    write = _req("file", "open", path=f"{CWD}/demo/out.txt", flags="w")
    assert not is_quiet_allow(write, shipped.evaluate(write))
    shadow = _req("file", "open", path="/etc/shadow", flags="r")
    assert not is_quiet_allow(shadow, shipped.evaluate(shadow))
    human = Verdict("allow", "session-x", "human:operator")
    assert not is_quiet_allow(read, human)


def test_unmatched_still_fail_closed() -> None:
    engine = PolicyEngine.from_dict({"rules": []})
    v = engine.evaluate(_req("net", "connect", host="8.8.8.8", port=53))
    assert v.action == "deny"
    assert v.actor == "fail-closed"


def test_argv_contains() -> None:
    engine = PolicyEngine.from_dict(
        {
            "rules": [
                {
                    "id": "deny-curl",
                    "match": {"kind": "shell", "argv_contains": "curl"},
                    "action": "deny",
                }
            ]
        }
    )
    v = engine.evaluate(_req("shell", "exec", argv=["curl", "https://x"]))
    assert v.action == "deny"
    assert v.rule_id == "deny-curl"
