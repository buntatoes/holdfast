#!/usr/bin/env python3
"""Isolation probe for Holdfast Jail.

Prints JSON facts about the kernel jail. Safe by construction: no payload,
no network send, no deletes outside /tmp. Run under `holdfast jail` or
`holdfast swarm`.
"""

from __future__ import annotations

import json
import os
import socket
import sys


def _exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False


def main() -> int:
    facts = {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "uid": os.getuid(),
        "cwd": os.getcwd(),
        "jail": os.environ.get("HOLDFAST_JAIL") == "1",
        "member": os.environ.get("HOLDFAST_JAIL_MEMBER"),
        "session": os.environ.get("HOLDFAST_SESSION"),
        "shadow_exists": _exists("/etc/shadow"),
        "passwd_exists": _exists("/etc/passwd"),
        "root_home_exists": _exists("/root"),
        "home_exists": _exists("/home"),
        "workspace_exists": _exists("/workspace") or os.path.isdir(os.getcwd()),
    }
    sys.stdout.write(json.dumps(facts, sort_keys=True) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
