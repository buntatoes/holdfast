from __future__ import annotations

import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from holdfast.cli import build_parser, jail_command_argv
from holdfast.util import find_jail_bin

REPO = Path(__file__).resolve().parents[3]
JAIL_DIR = REPO / "jail"
PROBE = REPO / "demo" / "swarm_probe.py"


def _ensure_jail() -> Path:
    binary = find_jail_bin()
    if not binary.is_file():
        subprocess.check_call(["make", "-C", str(JAIL_DIR)])
        binary = find_jail_bin()
    assert binary.is_file(), f"holdfast-jail missing at {binary}"
    return binary


def test_jail_is_proprietary() -> None:
    license_text = (JAIL_DIR / "LICENSE").read_text(encoding="utf-8")
    assert "proprietary software" in license_text
    assert "NOT licensed under" in license_text
    assert "Apache License 2.0" in license_text
    notice = (JAIL_DIR / "NOTICE").read_text(encoding="utf-8")
    assert "Proprietary" in notice
    src = (JAIL_DIR / "holdfast_jail.c").read_text(encoding="utf-8")
    assert "proprietary" in src.split("\n", 8)[1].lower()


def test_parser_has_jail_and_swarm() -> None:
    parser = build_parser()
    jail_args = parser.parse_args(["jail", "--net", "none", "--", "python3", "-c", "pass"])
    assert jail_args.command == "jail"
    assert jail_args.net == "none"
    swarm_args = parser.parse_args(["swarm", "--count", "4", "--", "true"])
    assert swarm_args.command == "swarm"
    assert swarm_args.count == 4
    wrap_args = parser.parse_args(["wrap", "--jail", "--", "true"])
    assert wrap_args.jail is True


def test_jail_command_requires_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing = tmp_path / "no-such-jail"
    monkeypatch.setenv("HOLDFAST_JAIL_BIN", str(missing))
    with pytest.raises(FileNotFoundError, match="holdfast-jail not found"):
        jail_command_argv(["true"], no_preload=True)


def test_kernel_jail_hides_host_secrets() -> None:
    binary = _ensure_jail()
    result = subprocess.run(
        [str(binary), "--no-preload", "--", sys.executable, str(PROBE)],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    facts = json.loads(result.stdout.strip().splitlines()[-1])
    assert facts["jail"] is True
    assert facts["pid"] == 1
    assert facts["hostname"] == "holdfast"
    assert facts["shadow_exists"] is False
    assert facts["root_home_exists"] is False
    assert facts["home_exists"] is False
    assert facts["passwd_exists"] is True


def test_jail_nss_does_not_leak_host_users() -> None:
    import getpass

    binary = _ensure_jail()
    host_user = getpass.getuser()
    script = r"""
from pathlib import Path
passwd = Path("/etc/passwd").read_text()
group = Path("/etc/group").read_text()
hosts = Path("/etc/hosts").read_text()
print("PASSWD", passwd.replace("\n", "|"))
print("GROUP", group.replace("\n", "|"))
print("HOSTS", hosts.replace("\n", "|"))
"""
    result = subprocess.run(
        [str(binary), "--no-preload", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "jail:/tmp:" in out
    assert "/home/" not in out
    if host_user not in {"root", "nobody"}:
        assert host_user not in out


def test_kernel_jail_blocks_unshare_and_mount() -> None:
    binary = _ensure_jail()
    script = r"""
import ctypes, ctypes.util, json, os
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
CLONE_NEWUSER = 0x10000000
unshare = libc.unshare(CLONE_NEWUSER)
unshare_err = ctypes.get_errno()
mount = libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, None)
mount_err = ctypes.get_errno()
print(json.dumps({"unshare": unshare, "unshare_err": unshare_err, "mount": mount, "mount_err": mount_err}))
"""
    result = subprocess.run(
        [str(binary), "--no-preload", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout.strip().splitlines()[-1])
    assert data["unshare"] == -1
    assert data["unshare_err"] == 1  # EPERM
    assert data["mount"] == -1
    assert data["mount_err"] == 1


def test_kernel_jail_kills_ptrace() -> None:
    binary = _ensure_jail()
    script = r"""
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
PTRACE_TRACEME = 0
libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
print("ptrace-allowed")
"""
    result = subprocess.run(
        [str(binary), "--no-preload", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert result.returncode != 0
    assert "ptrace-allowed" not in result.stdout
    assert result.returncode == 128 + signal.SIGSYS or result.returncode < 0 or result.returncode == 159


def test_net_none_blocks_connect() -> None:
    binary = _ensure_jail()
    script = r"""
import socket, errno
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("1.1.1.1", 443))
    print("connected")
except OSError as exc:
    print("blocked", exc.errno)
"""
    result = subprocess.run(
        [str(binary), "--no-preload", "--net", "none", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, result.stderr
    assert "connected" not in result.stdout
    assert "blocked" in result.stdout


def test_swarm_members_are_isolated() -> None:
    binary = _ensure_jail()
    procs = []
    for i in range(2):
        procs.append(
            subprocess.Popen(
                [
                    str(binary),
                    "--no-preload",
                    "--member",
                    str(i),
                    "--",
                    sys.executable,
                    str(PROBE),
                ],
                cwd=str(REPO),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    facts = []
    for proc in procs:
        out, err = proc.communicate(timeout=15)
        assert proc.returncode == 0, err
        facts.append(json.loads(out.strip().splitlines()[-1]))
    hostnames = {row["hostname"] for row in facts}
    assert hostnames == {"holdfast-0", "holdfast-1"}
    assert all(row["pid"] == 1 for row in facts)
    assert all(row["shadow_exists"] is False for row in facts)
    members = {row["member"] for row in facts}
    assert members == {"0", "1"}
