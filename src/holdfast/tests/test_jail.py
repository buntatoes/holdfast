from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from holdfast.util import find_jail_bin

JAIL_BIN = find_jail_bin()


@pytest.fixture(scope="module", autouse=True)
def ensure_jail_built():
    if not JAIL_BIN.is_file():
        subprocess.run(["make", "-C", "jail"], check=True)
    assert JAIL_BIN.is_file(), f"missing jail binary at {JAIL_BIN}"


def test_jail_binary_exists():
    assert JAIL_BIN.is_file()
    assert os.access(JAIL_BIN, os.X_OK)


def test_jail_basic_execution():
    res = subprocess.run(
        [str(JAIL_BIN), "--", "echo", "hello from jail"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "hello from jail" in res.stdout


def test_jail_pid_namespace_isolation():
    # Inside the PID namespace, child process should be PID 1
    res = subprocess.run(
        [str(JAIL_BIN), "--", "sh", "-c", "echo $$"],
        capture_output=True,
        text=True,
        check=True,
    )
    # The shell executed by child has PID 1 in the new pid namespace
    assert res.stdout.strip() == "1"


def test_jail_uts_hostname_isolation():
    res = subprocess.run(
        [str(JAIL_BIN), "--hostname", "swarm-node-42", "--", "hostname"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "swarm-node-42"


def test_jail_swarm_environment_variables():
    res = subprocess.run(
        [
            str(JAIL_BIN),
            "--swarm",
            "alpha-swarm",
            "--agent",
            "worker-3",
            "--",
            "sh",
            "-c",
            "echo $HOLDFAST_SWARM/$HOLDFAST_AGENT/$HOLDFAST_JAIL",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "alpha-swarm/worker-3/1"


def test_jail_network_isolation():
    # With --isolate-net, network interfaces should only have lo (down or isolated)
    py_code = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.settimeout(1)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 80))\n"
        "    print('connected')\n"
        "except OSError:\n"
        "    print('blocked')\n"
    )
    res = subprocess.run(
        [
            str(JAIL_BIN),
            "--isolate-net",
            "--",
            "python3",
            "-c",
            py_code,
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"stderr: {res.stderr}"
    assert res.stdout.strip() == "blocked"


def test_holdfast_cli_jail_command():
    res = subprocess.run(
        [
            sys.executable,
            "-m",
            "holdfast",
            "jail",
            "--swarm",
            "test-swarm",
            "--agent",
            "agent-0",
            "--no-wrap",
            "--",
            "sh",
            "-c",
            "echo $HOLDFAST_SWARM:$HOLDFAST_AGENT",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "test-swarm:agent-0"
