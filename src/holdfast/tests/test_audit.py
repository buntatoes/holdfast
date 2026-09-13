from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

from holdfast.audit import AuditLog, canonical_json, chain_hash, event_body


def _event(n: int) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": f"2026-09-13T02:40:00.{n:03d}Z",
        "kind": "file",
        "op": "open",
        "detail": {"path": f"/workspace/f{n}", "flags": "r"},
        "decision": "allow",
        "actor": "policy:allow-cwd-read",
        "session": "sess",
        "pid": 42,
    }


def test_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    log = AuditLog(path)
    assert path.parent.is_dir()
    rec = log.append(_event(0))
    assert path.is_file()
    assert rec["hash"]
    assert rec["prev_hash"] == ""


def test_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    first = log.append(_event(1))
    second = log.append(_event(2))
    assert first["prev_hash"] == ""
    assert second["prev_hash"] == first["hash"]
    body1 = event_body(first)
    body2 = event_body(second)
    assert first["hash"] == chain_hash("", body1)
    assert second["hash"] == chain_hash(first["hash"], body2)
    assert first["hash"] == chain_hash(
        "", {k: v for k, v in first.items() if k not in ("hash", "prev_hash")}
    )
    # Tampering the second body must not match the stored hash.
    tampered = dict(body2)
    tampered["decision"] = "deny"
    assert chain_hash(first["hash"], tampered) != second["hash"]


def test_canonical_stability() -> None:
    a = {"decision": "allow", "detail": {"b": 1, "a": 2}, "id": "x"}
    b = {"id": "x", "detail": {"a": 2, "b": 1}, "decision": "allow"}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"decision":"allow","detail":{"a":2,"b":1},"id":"x"}'


def test_reopen_continues_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    first = log.append(_event(3))
    log2 = AuditLog(path)
    second = log2.append(_event(4))
    assert second["prev_hash"] == first["hash"]


def test_thread_safe_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    n_threads = 4
    n_each = 25

    def worker() -> None:
        for i in range(n_each):
            log.append(_event(i))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == n_threads * n_each
    prev = ""
    seen = set()
    for line in lines:
        rec = json.loads(line)
        assert rec["hash"] not in seen
        seen.add(rec["hash"])
        assert rec["prev_hash"] == prev
        body = event_body(rec)
        assert rec["hash"] == chain_hash(prev, body)
        prev = rec["hash"]
    assert log.last_hash == prev


def test_tail(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(10):
        log.append(_event(i))
    assert len(log.tail(4)) == 4
    assert log.tail(4)[-1]["detail"]["path"] == "/workspace/f9"
