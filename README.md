# Holdfast

**Agents propose. You decide.**

Holdfast is a Linux enforcement layer that sits under a coding-agent process.
File, shell, and network operations pause until policy or a human allows them.
The default is fail-closed.

You already do not trust a model to keep its promises. Holdfast does not ask
it to. Prompts are not a security boundary. Holdfast is.

This is for teams that want agents on a repo without handing them the
machine: the agent can *propose* `open`, `exec`, and `connect`; an operator
verifies each one that policy does not already decide.

## Why

Hoping the model behaves is not a control. A jailbreak, a confused tool call,
or a “helpful” exfil script will ignore the system prompt. Holdfast does not
read the prompt. It intercepts the syscalls.

- **Prompt-proof.** Policy and a human decide. The model’s intent is
  irrelevant.
- **Fail-closed.** Missing daemon, timeout, or unknown operation: deny.
- **Visible.** Every decision is on the operator desk and in an append-only
  audit log.

Ethos, same as a serious agent harness: **agents propose, humans verify.**
Holdfast is the enforcement cut of that idea — not a workflow tool, a
gate on the process.

## Architecture

```
  agent (python, node, …)
           │
           │  libc open / exec / connect
           ▼
    libholdfast.so          LD_PRELOAD
           │
           │  newline JSON on a Unix socket
           ▼
       holdfastd            policy, wait-for-human, audit
           │
           ├── operator desk (console/)
           └── append-only JSONL audit log
```

| Piece | Role |
| --- | --- |
| `preload/` | C library (`libholdfast.so`). Intercepts libc, talks to the daemon, uses `dlsym(RTLD_NEXT)` and a re-entrancy guard so its own IPC is not intercepted. |
| `src/holdfast/` | Daemon, policy engine, audit chain, CLI (`holdfastd`, `holdfast`). |
| `console/` | Operator desk — Next.js UI for the pending queue. |
| `policies/default.yaml` | Shipped policy. First match wins: `allow`, `deny`, `ask`. |
| `src/holdfast_edge/` | Optional Edge mode — scores swarm-like web traffic in front of a site. Separate from wrap. |
| `policies/edge.yaml` | Edge policy. Default shadow. |
| `EDGE.md` | Edge operator notes. |
| `demo/` | Naughty agent (blocked path) and well-behaved agent (contrast). |
| `systemd/holdfast.service` | Linux unit. |

The preload and daemon speak newline-delimited JSON on `$HOLDFAST_SOCK`
(default `/tmp/holdfast.sock`). The console talks to the daemon over HTTP
on `http://127.0.0.1:47821` (WebSocket at `/api/stream`). Bind the desk and daemon to localhost in production.

Linux only. The daemon refuses to start on any other OS.

## Install (Linux)

Build toolchain, Python 3, and Node.js (for the desk).

```bash
make -C preload          # → preload/libholdfast.so
python3 -m pip install -e .
```

That puts `holdfastd` and `holdfast` on your `PATH`.

```bash
cd console
npm install
npm run dev              # operator desk at http://127.0.0.1:43123
```

Optional: install the unit from `systemd/holdfast.service`.

## Run

```bash
# terminal 1 — daemon (socket + HTTP API)
holdfastd

# terminal 2 — operator desk
cd console && npm run dev

# terminal 3 — wrap whatever you were going to run
holdfast wrap -- python3 demo/naughty_agent.py
holdfast wrap -- python3 demo/well_behaved_agent.py
# or the bundled naughty run:
holdfast demo
```

`holdfast wrap` sets `LD_PRELOAD`, `HOLDFAST_SOCK`, and `HOLDFAST_SESSION`
and execs the command. Unwrapped processes are not gated.

```bash
holdfast status
holdfast audit           # or: holdfast audit --json
```

## How to approve

The desk is the queue. Each pending card shows the process (`pid`, `exe`,
`cwd`) and the operation in plain text: a path, an argv, or `host:port`.

- **Allow** is the primary action.
- **Deny** is destructive (the syscall fails; the agent sees `EPERM`).
- **Remember for this session** (`remember_session`) adds an in-memory rule
  ahead of the file, same kind + op + normalized target, so repeats in this
  session do not prompt again.

If nobody answers within 300 seconds, Holdfast denies. If the Unix socket is
missing, the preload denies. There is no silent pass.

## Audit log

Append-only JSONL at `$HOLDFAST_AUDIT`, or
`~/.local/share/holdfast/audit.jsonl` if unset.

Each line is one event. Lines chain: `prev_hash` plus SHA-256 of the
canonical line. Never rewrite the file.

Policy-allowed file reads are enforced but omitted from the default audit
stream so a wrapped interpreter does not flood the log. Writes, exec, net,
denials, and human decisions are always recorded.

## Default policy

Shipped in `policies/default.yaml`. First match wins.

| Match | Action |
| --- | --- |
| File **read** under the session cwd | allow (quiet) |
| Connect to the Holdfast daemon host/port and Holdfast’s own Unix sockets | allow |
| Path prefixes `/etc/shadow`, `/root`, SSH keys, `~/.aws`, `~/.gnupg` | deny |
| Remaining file **reads** (stdlib, `/proc`, `/etc/passwd`, …) | allow (quiet) |
| Every other file write/delete, every `exec`, every `connect` | ask |

That is the whole point of the demo: a write under `demo/`, `exec` of `id`
or `curl`, and a TCP `connect` all stop for a human unless you already
allowed them this session. Reading `demo/brief.txt` does not.

## Demo

`demo/naughty_agent.py` prints a plan, then tries:

1. Workspace write (`demo/out.txt`) and a dummy payload under `/tmp`
2. Read `/etc/shadow`
3. `os.system("id")`
4. `curl http://203.0.113.1:9/` (RFC 5737 TEST-NET-3; will fail even if exec is allowed)
5. `socket.connect` to `1.1.1.1:443` (handshake only, no bytes sent)

It catches `EPERM` / permission errors, prints `Holdfast blocked: …`,
summarizes blocked vs succeeded vs other failures, and **exits 0**. It does
not delete files, does not use a real exfil host, and does not send a
payload.

`demo/well_behaved_agent.py` only reads `demo/brief.txt` and writes
`demo/out-ok.txt`. Under the default policy the read is allowed; the write
still asks.

## Limitations

This is a first slice, not a kernel sandbox.

- **`LD_PRELOAD` is not a jail.** It wraps libc. It does not wrap the
  kernel. A process that issues raw syscalls, or that is not dynamically
  linked against glibc/musl libc in the usual way, is outside this gate.
- **Static binaries and most Go binaries may bypass libc** and therefore
  bypass the preload. Do not point Holdfast at `CGO_ENABLED=0` Go agents
  and assume they are held.
- Unwrapped children you did not `holdfast wrap` are not held. Policy is
per wrapped session, not a machine-wide MAC.

`holdfast wrap` disables Python's posix_spawn/vfork helpers. glibc
`posix_spawn` uses vfork; the child shares memory with the parent until
exec and can rewrite the agent's `connect` PLT, which would let later
network calls skip the gate. Node and other runtimes can still hit that
if they vfork.
- The desk and daemon are local operator tools, not a multi-tenant
  control plane.

If you need ptrace, seccomp, or a user namespace, that is a different
product. Holdfast is the libc cut you can put under a Python or Node agent
today.

## Holdfast Edge

A second mode, separate package. Edge sits in front of a website and scores
swarm behavior — bursts, fan-out, retry loops, goal-seeking walks. It does
not ban on User-Agent claims.

Decisions are **allow**, **challenge**, or **deny**. Uncertain traffic is
challenged, not blocked. A first hit is never a silent ban. Default mode is
**shadow**: log what would happen, let every request through. Flip to
**enforce** only after the log looks right.

```bash
holdfast-edge proxy --origin http://127.0.0.1:8080 --mode shadow
```

Policy: `policies/edge.yaml`. Listen: `127.0.0.1:47831` (not the daemon port).
A bad edge rule cannot brick `holdfast wrap`. See `EDGE.md`.

## License

Apache-2.0
