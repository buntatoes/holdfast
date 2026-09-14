# Holdfast protocol (shared contract)

Holdfast is a Linux daemon that sits under an agent process. File, shell, and
network operations pause until policy or a human allows them. Default is
fail-closed. Ethos: agents propose, humans verify.

## Layout

- `preload/` — C `LD_PRELOAD` library (`libholdfast.so`)
- `src/holdfast/` — Python package: daemon, policy, audit, CLI
- `console/` — Next.js operator UI (Tailwind + shadcn/ui)
- `policies/default.yaml` — shipped policy
- `demo/` — a naughty agent that tries file/shell/net
- `systemd/holdfast.service` — Linux unit

## Unix socket (enforcement)

Path: `$HOLDFAST_SOCK` or `/tmp/holdfast.sock`

Newline-delimited JSON. The preloaded process MUST use `dlsym(RTLD_NEXT)`
for real syscalls and a thread-local re-entrancy guard so its own IPC is
not intercepted.

### Request (preload → daemon)

```json
{
  "id": "uuid-v4",
  "session": "session-id",
  "kind": "file" | "shell" | "net",
  "op": "open" | "creat" | "unlink" | "rename" | "exec" | "connect",
  "pid": 1234,
  "ppid": 1200,
  "exe": "/usr/bin/python3",
  "cwd": "/workspace",
  "detail": {},
  "ts": "2026-09-13T02:40:00.000Z"
}
```

`detail` by kind:

- file: `{"path":"/abs/path","flags":"w","mode":420}` (`flags` is `r`/`w`/`rw`)
- shell: `{"argv":["curl","https://evil.example"],"resolved":"/usr/bin/curl"}`
- net: `{"host":"93.184.216.34","port":443,"family":"tcp"}`

### Response (daemon → preload)

```json
{"id":"uuid-v4","decision":"allow"}
{"id":"uuid-v4","decision":"deny","reason":"human denied"}
```

If the socket is missing, the preload **denies** (fail-closed). Timeout 300s
then deny.

## HTTP API (operator console → daemon)

Base: `http://127.0.0.1:47821`

- `GET /health` → `{ok, linux, version}`
- `GET /api/pending` → `{items: Request[]}` (waiting on a human)
- `POST /api/decide` body `{id, decision: "allow"|"deny", actor, note?, remember_session?: bool}`
- `GET /api/audit?limit=100` → `{items: AuditEvent[]}`
- `GET /api/session` → `{id, pid, command, started_at, stats}`
- `GET /api/policy` → current policy summary
- `WS /api/stream` → JSON events: `pending`, `decided`, `audit`, `session`

CORS: allow the console origin. Prefer localhost in production.

## Policy (`policies/default.yaml`)

First match wins. Actions: `allow`, `deny`, `ask`.

Default shipped policy:

- allow: file **read** under the session cwd
- allow: connect to the Holdfast daemon host/port and Unix sockets used by Holdfast
- deny: path prefixes `/etc/shadow`, `/root`, SSH keys, `~/.aws`, `~/.gnupg`
- allow: remaining file **reads** (interpreter, `/usr`, `/etc/passwd`, `/proc`, …) so a wrapped Python/Node agent can start
- ask: every other file write/delete, every `exec`, every `connect`

Policy-allowed file reads are enforced but omitted from the default audit stream so the desk stays readable. Writes, exec, net, denials, and human decisions are always logged.

`remember_session` on a human allow/deny adds an in-memory session rule
ahead of the file (same kind+op+normalized target).

## Audit log

Append-only JSONL at `$HOLDFAST_AUDIT` or `~/.local/share/holdfast/audit.jsonl`.
Each line is one event. Chain: `prev_hash` + sha256 of the canonical line.
Never rewrite. Fields: id, ts, kind, op, detail, decision, actor
(`policy:<rule>` | `human:<name>` | `timeout` | `fail-closed`), session, pid.

## CLI

```
holdfastd          # start daemon (socket + HTTP)
holdfast wrap -- <cmd...>   # set LD_PRELOAD + HOLDFAST_SOCK + HOLDFAST_SESSION and exec
holdfast status
holdfast audit [--json]
holdfast demo      # run demo/naughty_agent.py under wrap
```

Linux only: refuse to start on non-Linux with a clear error.

## UI copy

Serious, operator-grade. No lorem, no “welcome to your app”.
Headline: “Agents propose. You decide.”
Pending card states: empty queue, waiting, decided flash, error if daemon down.
Allow is primary; Deny is destructive. Show argv/path/host plainly.
