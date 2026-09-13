"""Holdfast daemon: Unix socket enforcement + HTTP operator API."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from holdfast import __version__
from holdfast.audit import AuditLog
from holdfast.policy import PolicyEngine, Verdict
from holdfast.util import (
    decision_timeout,
    default_audit_path,
    default_policy_path,
    http_host,
    http_port,
    now_iso,
    sock_path,
)

log = logging.getLogger("holdfast")

DecideAction = Literal["allow", "deny"]


class DecideIn(BaseModel):
    id: str
    decision: DecideAction
    actor: str
    note: str | None = None
    remember_session: bool = False


@dataclass
class PendingSlot:
    request: dict[str, Any]
    future: asyncio.Future
    parked_at: str


@dataclass
class SessionInfo:
    id: str
    pid: int | None
    command: str | None
    started_at: str
    last_seen: str
    stats: dict[str, int] = field(
        default_factory=lambda: {"allow": 0, "deny": 0, "ask": 0}
    )


@dataclass
class HoldfastState:
    policy: PolicyEngine
    audit: AuditLog
    pending: dict[str, PendingSlot] = field(default_factory=dict)
    sessions: dict[str, SessionInfo] = field(default_factory=dict)
    subscribers: set[WebSocket] = field(default_factory=set)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    started_at: str = field(default_factory=now_iso)

    def current_session(self) -> SessionInfo | None:
        if not self.sessions:
            return None
        return max(self.sessions.values(), key=lambda s: s.last_seen)

    def session_public(self, session: SessionInfo | None = None) -> dict[str, Any]:
        sess = session or self.current_session()
        pending_n = 0
        if sess is not None:
            pending_n = sum(
                1
                for slot in self.pending.values()
                if slot.request.get("session") == sess.id
            )
            return {
                "id": sess.id,
                "pid": sess.pid,
                "command": sess.command,
                "started_at": sess.started_at,
                "stats": {**sess.stats, "pending": pending_n},
            }
        return {
            "id": None,
            "pid": None,
            "command": None,
            "started_at": None,
            "stats": {
                "allow": 0,
                "deny": 0,
                "ask": 0,
                "pending": len(self.pending),
            },
        }

    def touch_session(self, request: dict[str, Any]) -> SessionInfo:
        sid = str(request.get("session") or "unknown")
        now = now_iso()
        detail = request.get("detail") or {}
        command = request.get("exe")
        argv = detail.get("argv") if isinstance(detail, dict) else None
        if argv:
            command = " ".join(str(x) for x in argv)
        sess = self.sessions.get(sid)
        if sess is None:
            sess = SessionInfo(
                id=sid,
                pid=request.get("pid"),
                command=command,
                started_at=now,
                last_seen=now,
            )
            self.sessions[sid] = sess
        else:
            sess.last_seen = now
            if request.get("pid") is not None:
                sess.pid = request.get("pid")
            if command and (not sess.command or request.get("kind") == "shell"):
                sess.command = command
        return sess

    def bump(self, session: SessionInfo | None, key: str) -> None:
        if session is None:
            return
        session.stats[key] = session.stats.get(key, 0) + 1


def load_state() -> HoldfastState:
    policy_path = default_policy_path()
    if not policy_path.is_file():
        raise FileNotFoundError(
            f"holdfastd: policy file not found at {policy_path}. "
            "Set HOLDFAST_POLICY or install policies/default.yaml."
        )
    policy = PolicyEngine.from_yaml(policy_path)
    audit = AuditLog.open(default_audit_path())
    return HoldfastState(policy=policy, audit=audit)


async def broadcast(state: HoldfastState, event: dict[str, Any]) -> None:
    payload = json.dumps(event, default=str)
    dead: list[WebSocket] = []
    for ws in list(state.subscribers):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        state.subscribers.discard(ws)


def _audit_from_request(
    state: HoldfastState,
    request: dict[str, Any],
    decision: str,
    actor: str,
    note: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "id": request.get("id"),
        "ts": now_iso(),
        "kind": request.get("kind"),
        "op": request.get("op"),
        "detail": request.get("detail") or {},
        "decision": decision,
        "actor": actor,
        "session": request.get("session"),
        "pid": request.get("pid"),
    }
    if note:
        event["note"] = note
    return state.audit.append(event)


async def record_and_notify(
    state: HoldfastState,
    request: dict[str, Any],
    decision: str,
    actor: str,
    note: str | None = None,
    session: SessionInfo | None = None,
) -> dict[str, Any]:
    record = _audit_from_request(state, request, decision, actor, note)
    await broadcast(state, {"type": "audit", "event": record})
    await broadcast(
        state,
        {"type": "decided", "id": request.get("id"), "decision": decision, "actor": actor, "note": note},
    )
    await broadcast(state, {"type": "session", **state.session_public(session)})
    return record


async def handle_preload(
    state: HoldfastState,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                writer.write(
                    b'{"id":"","decision":"deny","reason":"invalid json"}\n'
                )
                await writer.drain()
                continue
            if not isinstance(request, dict):
                writer.write(
                    b'{"id":"","decision":"deny","reason":"invalid request"}\n'
                )
                await writer.drain()
                continue
            try:
                response = await decide_request(state, request)
            except Exception:
                log.exception("failed to decide preload request")
                response = {
                    "id": str(request.get("id") or ""),
                    "decision": "deny",
                    "reason": "internal error",
                }
            writer.write((json.dumps(response, separators=(",", ":")) + "\n").encode())
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        log.debug("preload client disconnected")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def is_quiet_allow(request: dict[str, Any], verdict: Verdict) -> bool:
    """Ordinary policy-allowed file reads would drown the audit log."""
    if verdict.action != "allow":
        return False
    if request.get("kind") != "file":
        return False
    detail = request.get("detail") if isinstance(request.get("detail"), dict) else {}
    if str(detail.get("flags") or "") != "r":
        return False
    return (verdict.actor or "").startswith("policy:")


async def decide_request(state: HoldfastState, request: dict[str, Any]) -> dict[str, Any]:
    req_id = str(request.get("id") or "")
    session = state.touch_session(request)
    verdict: Verdict = state.policy.evaluate(request)

    if verdict.action in ("allow", "deny"):
        if is_quiet_allow(request, verdict):
            resp = {"id": req_id, "decision": verdict.action}
            return resp
        state.bump(session, verdict.action)
        await record_and_notify(
            state, request, verdict.action, verdict.actor, session=session
        )
        resp: dict[str, Any] = {"id": req_id, "decision": verdict.action}
        if verdict.action == "deny":
            resp["reason"] = verdict.actor
        return resp

    state.bump(session, "ask")
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    slot = PendingSlot(request=request, future=future, parked_at=now_iso())
    async with state.lock:
        state.pending[req_id] = slot
    await broadcast(state, {"type": "pending", "request": request})
    await broadcast(state, {"type": "session", **state.session_public(session)})

    timeout = decision_timeout()
    decision: str = "deny"
    actor: str = "timeout"
    note: str | None = None
    try:
        result = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        decision = result["decision"]
        actor = result["actor"]
        note = result.get("note")
    except asyncio.TimeoutError:
        decision = "deny"
        actor = "timeout"
        note = None
        if not future.done():
            future.set_result(
                {"decision": "deny", "actor": "timeout", "note": None, "remember_session": False}
            )
    except asyncio.CancelledError:
        async with state.lock:
            state.pending.pop(req_id, None)
        raise
    finally:
        async with state.lock:
            state.pending.pop(req_id, None)

    state.bump(session, decision)
    await record_and_notify(state, request, decision, actor, note, session=session)
    resp = {"id": req_id, "decision": decision}
    if decision == "deny":
        resp["reason"] = note or actor
        if actor == "timeout":
            resp["reason"] = "timeout"
        elif actor.startswith("human:"):
            resp["reason"] = note or "human denied"
    return resp


async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s holdfast: %(message)s",
    )
    state = getattr(app.state, "hf", None)
    if state is None:
        state = load_state()
        app.state.hf = state

    path = sock_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    async def on_preload(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await handle_preload(state, reader, writer)
        except Exception:
            log.exception("preload client error")

    server = await asyncio.start_unix_server(on_preload, path=path, start_serving=False)
    try:
        os.chmod(path, 0o666)
    except OSError:
        log.warning("could not chmod %s", path)
    app.state.unix_server = server
    serve_task = asyncio.create_task(server.serve_forever(), name="holdfast-unix")
    log.info("unix socket %s", path)
    log.info("http %s:%s", http_host(), http_port())
    try:
        yield
    finally:
        serve_task.cancel()
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


app = FastAPI(title="Holdfast", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _hf(request: Request) -> HoldfastState:
    return request.app.state.hf


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "linux": sys.platform == "linux",
        "version": __version__,
    }


@app.get("/api/pending")
async def pending(request: Request) -> dict[str, Any]:
    state = _hf(request)
    items = []
    for slot in state.pending.values():
        item = dict(slot.request)
        item["parked_at"] = slot.parked_at
        items.append(item)
    items.sort(key=lambda x: x.get("parked_at") or "")
    return {"items": items}


@app.post("/api/decide")
async def decide(body: DecideIn, request: Request) -> dict[str, Any]:
    state = _hf(request)
    actor = body.actor if body.actor.startswith("human:") else f"human:{body.actor}"
    async with state.lock:
        slot = state.pending.get(body.id)
        if slot is None:
            raise HTTPException(status_code=404, detail="unknown pending id")
        if slot.future.done():
            raise HTTPException(status_code=409, detail="already decided")
        if body.remember_session:
            state.policy.remember_session(slot.request, body.decision)
        slot.future.set_result(
            {
                "decision": body.decision,
                "actor": actor,
                "note": body.note,
                "remember_session": body.remember_session,
            }
        )
    return {
        "ok": True,
        "id": body.id,
        "decision": body.decision,
        "actor": actor,
        "remember_session": body.remember_session,
    }


@app.get("/api/audit")
async def audit_tail(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    state = _hf(request)
    return {"items": state.audit.tail(limit)}


@app.get("/api/session")
async def session(request: Request) -> dict[str, Any]:
    return _hf(request).session_public()


@app.get("/api/policy")
async def policy(request: Request) -> dict[str, Any]:
    return _hf(request).policy.summary()


@app.websocket("/api/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    state: HoldfastState = ws.app.state.hf
    state.subscribers.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "session", **state.session_public()}))
        for slot in state.pending.values():
            await ws.send_text(json.dumps({"type": "pending", "request": slot.request}))
        while True:
            await ws.receive()
    except WebSocketDisconnect:
        pass
    except Exception:
        log.debug("websocket closed", exc_info=True)
    finally:
        state.subscribers.discard(ws)


def main() -> None:
    if sys.platform != "linux":
        print(
            f"error: holdfastd is Linux-only (LD_PRELOAD enforcement). "
            f"Refusing to start on platform {sys.platform!r}.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        app.state.hf = load_state()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    uvicorn.run(
        app,
        host=http_host(),
        port=http_port(),
        log_level="info",
    )


if __name__ == "__main__":
    main()
