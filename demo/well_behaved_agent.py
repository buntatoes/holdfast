#!/usr/bin/env python3
"""Holdfast demo: an agent that stays inside demo/.

Reads demo/brief.txt and writes demo/out-ok.txt. No shell, no network, no
paths outside this directory. Contrast with demo/naughty_agent.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "brief.txt"
DST = HERE / "out-ok.txt"


def main() -> int:
    print("=== Holdfast demo — well-behaved agent ===", flush=True)
    print(f"I will read {SRC} and write {DST}.", flush=True)
    print("No shell, no network, no files outside demo/.", flush=True)
    print(flush=True)

    print(f"[file] read {SRC}", flush=True)
    text = SRC.read_text(encoding="utf-8")
    print(f"  -> ok  {len(text)} bytes", flush=True)

    note = (
        "well-behaved agent finished.\n"
        f"read: {SRC.name} ({len(text)} bytes)\n"
        "wrote this file; did not exec or connect.\n"
    )
    print(f"[file] write {DST}", flush=True)
    DST.write_text(note, encoding="utf-8")
    print("  -> ok  wrote out-ok.txt", flush=True)

    print(flush=True)
    print("=== summary ===", flush=True)
    print("  ok        read demo/brief.txt", flush=True)
    print("  ok        write demo/out-ok.txt", flush=True)
    print("blocked=0  succeeded=2  other_failures=0", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
