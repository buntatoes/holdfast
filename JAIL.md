# Holdfast Jail (Swarm Sandbox)

**Kernel-level containment for Agent Swarms.**

Holdfast Jail (`jail/holdfast-jail`) is a native Linux sandbox layer built in C
using Linux kernel namespaces. It complements the `libholdfast.so` LD_PRELOAD
libc interception mechanism with true process, mount, network, and user isolation.

## Why a Jail?

While `LD_PRELOAD` intercepts dynamic libc calls (`open`, `exec`, `connect`), it is not
a kernel security boundary:
- Statically linked or Go binaries can bypass libc syscall wrappers.
- In multi-agent swarms, agents could inspect each other's processes via `/proc` or communicate via shared host IPC/signals.

Holdfast Jail establishes actual kernel isolation boundaries:
1. **PID namespace:** The agent process becomes PID 1 in a private PID tree and cannot see, signal, or trace host processes or other swarm agents.
2. **Mount namespace:** Fresh, unshared `/proc` with `MS_NOSUID | MS_NOEXEC | MS_NODEV`, and isolated root mount point.
3. **User namespace:** Unprivileged root mapping (maps current UID/GID to container root 0 without host privileges).
4. **UTS namespace:** Dedicated hostname per agent / swarm node.
5. **IPC namespace:** Isolated System V IPC and POSIX message queues.
6. **Network namespace (optional with `--isolate-net`):** Completely cuts off raw host network interfaces (loopback only, isolated from host sockets).

## Defense-in-Depth Architecture

```
  ┌────────────────────────────────────────────────────────┐
  │ Host System (Kernel)                                   │
  │                                                        │
  │  holdfastd (daemon & operator desk)                    │
  │     ▲                                                  │
  │     │ Unix socket IPC                                  │
  │  ┌──┴───────────────────────────────────────────────┐  │
  │  │ Holdfast Jail (User/PID/MNT/UTS/IPC Namespace)   │  │
  │  │                                                  │  │
  │  │   Agent Process (PID 1 inside jail)              │  │
  │  │      │                                           │  │
  │  │      ▼ libc calls                                │  │
  │  │   libholdfast.so (LD_PRELOAD gate)               │  │
  │  │                                                  │  │
  │  └──────────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────────┘
```

When run with `holdfast jail`, the target process is wrapped in both the kernel
namespace jail *and* the `libholdfast.so` policy enforcement layer by default.

## Usage

### Direct CLI via Holdfast

```bash
# Run an agent inside an isolated jail
holdfast jail -- python3 agent.py

# Swarm mode: identify swarm cluster and agent worker
holdfast jail --swarm alpha --agent worker-1 -- python3 agent.py
holdfast jail --swarm alpha --agent worker-2 -- python3 agent.py

# Hardened network isolation: completely cut off host network namespace
holdfast jail --isolate-net -- python3 agent.py

# Read-only root filesystem
holdfast jail --ro-root -- python3 agent.py

# Specify workspace directory
holdfast jail --workspace /workspace/sandbox -- python3 agent.py

# Pure namespace jail without LD_PRELOAD interception
holdfast jail --no-wrap -- python3 agent.py
```

### Standalone Binary

```bash
make -C jail
./jail/holdfast-jail --swarm alpha --agent worker-1 -v -- ps aux
```

Options:
- `--swarm <id>`: Swarm cluster identifier (exposed as `$HOLDFAST_SWARM` and part of `$HOLDFAST_SESSION`).
- `--agent <id>`: Agent worker identifier (exposed as `$HOLDFAST_AGENT`).
- `--workspace <dir>`: Sets working directory inside the jail.
- `--hostname <name>`: Custom hostname in UTS namespace (default: `holdfast-agent`).
- `--isolate-net`: Unshare network namespace (`CLONE_NEWNET`).
- `--ro-root`: Mount root filesystem read-only.
- `--verbose`, `-v`: Print jail configuration diagnostics.

## Policy Integration for Swarms

In `policies/default.yaml`, rules can target specific swarms or individual agents:

```yaml
rules:
  # Deny all external network connects from worker swarms
  - id: deny-worker-swarm-net
    match:
      kind: net
      op: connect
      swarm: worker-swarm
    action: deny

  # Allow lead agent to connect
  - id: allow-lead-agent-net
    match:
      kind: net
      op: connect
      swarm: lead-swarm
    action: allow
```
