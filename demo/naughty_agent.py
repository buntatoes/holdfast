#!/usr/bin/env python3
"""Holdfast demo: a coding agent that looks like it left the rails.

Safe by construction. The payload is fabricated, the HTTP target is RFC 5737
TEST-NET-3 (not routed), and nothing is deleted or overwritten outside this
demo's own output file. Run under `holdfast wrap` or `holdfast demo`.
"""

from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_PATH = HERE / "out.txt"
EXFIL_PATH = Path("/tmp/holdfast-demo-exfil.txt")
SHADOW_PATH = Path("/etc/shadow")
TESTNET_URL = "http://203.0.113.1:9/"  # RFC 5737 TEST-NET-3, discard port
CONNECT_HOST = "1.1.1.1"
CONNECT_PORT = 443

BLOCKED = "blocked"
OK = "ok"
FAILED = "failed"


def _is_blocked(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES):
        return True
    return False


def _blocked_msg(exc: BaseException) -> str:
    return f"Holdfast blocked: {exc}"


def main() -> int:
    print("=== Holdfast demo — naughty agent ===", flush=True)
    print(
        "I am a coding agent. I found what look like secrets and I am going "
        "to copy them out, read the shadow file, spawn a shell, and phone home.",
        flush=True,
    )
    print("This is a demonstration. No real exfil. TEST-NET / dummy payload only.", flush=True)
    print(flush=True)
    print("Plan:", flush=True)
    print(f"  1. write {OUT_PATH} and {EXFIL_PATH}", flush=True)
    print(f"  2. read {SHADOW_PATH}", flush=True)
    print("  3. os.system('/usr/bin/id')", flush=True)
    print(f"  4. subprocess curl {TESTNET_URL}", flush=True)
    print(f"  5. socket.connect {CONNECT_HOST}:{CONNECT_PORT}", flush=True)
    print(flush=True)

    results: list[tuple[str, str, str]] = []

    def record(name: str, status: str, detail: str) -> None:
        results.append((name, status, detail))
        tag = {"blocked": "BLOCKED", "ok": "ok     ", "failed": "failed "}[status]
        print(f"  -> {tag}  {name}: {detail}", flush=True)

    # --- file write (workspace + /tmp dummy payload) ---
    payload = (
        "# holdfast demo — fabricated payload, not a real secret\n"
        "session_token=DEMO-NOT-A-SECRET\n"
        "note=RFC5737 / example.invalid; do not treat as exfil\n"
    )
    print(f"[file] writing fabricated payload to {OUT_PATH}", flush=True)
    try:
        OUT_PATH.write_text(payload, encoding="utf-8")
        record(f"write {OUT_PATH}", OK, "wrote dummy payload")
    except OSError as exc:
        if _is_blocked(exc):
            record(f"write {OUT_PATH}", BLOCKED, _blocked_msg(exc))
        else:
            record(f"write {OUT_PATH}", FAILED, str(exc))

    print(f"[file] writing fabricated payload to {EXFIL_PATH}", flush=True)
    try:
        EXFIL_PATH.write_text(payload, encoding="utf-8")
        record(f"write {EXFIL_PATH}", OK, "wrote dummy payload")
    except OSError as exc:
        if _is_blocked(exc):
            record(f"write {EXFIL_PATH}", BLOCKED, _blocked_msg(exc))
        else:
            record(f"write {EXFIL_PATH}", FAILED, str(exc))

    # --- sensitive read ---
    print(f"[file] reading {SHADOW_PATH}", flush=True)
    try:
        data = SHADOW_PATH.read_bytes()
        record(
            f"read {SHADOW_PATH}",
            OK,
            f"read {len(data)} bytes (unexpected without root / policy allow)",
        )
    except OSError as exc:
        if _is_blocked(exc):
            record(f"read {SHADOW_PATH}", BLOCKED, _blocked_msg(exc))
        else:
            record(f"read {SHADOW_PATH}", FAILED, str(exc))

    # --- shell: id via os.system ---
    print("[shell] os.system('/usr/bin/id')", flush=True)
    try:
        rc = os.system("/usr/bin/id")
        if rc == 0:
            record("os.system id", OK, "exit 0")
        else:
            # execve EPERM often surfaces as a 127-style wait status, not an exception
            shifted = rc >> 8
            if shifted in (126, 127) or rc in (errno.EPERM, errno.EACCES):
                record(
                    "os.system id",
                    BLOCKED,
                    f"Holdfast blocked: os.system returned {rc} (wait status)",
                )
            else:
                record("os.system id", FAILED, f"exit status {rc}")
    except OSError as exc:
        if _is_blocked(exc):
            record("os.system id", BLOCKED, _blocked_msg(exc))
        else:
            record("os.system id", FAILED, str(exc))

    # --- shell: curl TEST-NET via subprocess ---
    curl_bin = "/usr/bin/curl" if os.path.isfile("/usr/bin/curl") else "curl"
    curl_argv = [
        curl_bin,
        "-sS",
        "--max-time",
        "2",
        "--connect-timeout",
        "2",
        TESTNET_URL,
    ]
    print(f"[shell] subprocess {curl_argv!r}", flush=True)
    try:
        completed = subprocess.run(
            curl_argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if completed.returncode == 0:
            record("subprocess curl", OK, "unexpected success against TEST-NET")
        else:
            err = (completed.stderr or completed.stdout or "").strip().splitlines()
            tail = err[-1] if err else f"exit {completed.returncode}"
            record(
                "subprocess curl",
                FAILED,
                f"command ran, then failed (expected): {tail}",
            )
    except FileNotFoundError as exc:
        record("subprocess curl", FAILED, f"curl not installed: {exc}")
    except subprocess.TimeoutExpired:
        record("subprocess curl", FAILED, "timed out after exec (connect not blocked)")
    except OSError as exc:
        if _is_blocked(exc):
            record("subprocess curl", BLOCKED, _blocked_msg(exc))
        else:
            record("subprocess curl", FAILED, str(exc))

    # --- net: TCP connect, no payload ---
    print(f"[net] socket.connect(({CONNECT_HOST!r}, {CONNECT_PORT})) — handshake only", flush=True)
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((CONNECT_HOST, CONNECT_PORT))
        record(
            f"connect {CONNECT_HOST}:{CONNECT_PORT}",
            OK,
            "TCP handshake succeeded (no bytes sent)",
        )
    except OSError as exc:
        if _is_blocked(exc):
            record(f"connect {CONNECT_HOST}:{CONNECT_PORT}", BLOCKED, _blocked_msg(exc))
        else:
            record(f"connect {CONNECT_HOST}:{CONNECT_PORT}", FAILED, str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    blocked = sum(1 for _, s, _ in results if s == BLOCKED)
    succeeded = sum(1 for _, s, _ in results if s == OK)
    failed = sum(1 for _, s, _ in results if s == FAILED)

    print(flush=True)
    print("=== summary ===", flush=True)
    for name, status, detail in results:
        print(f"  {status:8}  {name} — {detail}", flush=True)
    print(flush=True)
    print(
        f"blocked={blocked}  succeeded={succeeded}  other_failures={failed}",
        flush=True,
    )
    print("exit 0 (attempts finished; this process does not fail the demo)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
