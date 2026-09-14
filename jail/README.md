# Holdfast Jail

Proprietary kernel jail for Holdfast agent swarms. This directory is **not**
Apache 2.0. See [LICENSE](LICENSE).

Jail puts each agent in Linux user, mount, pid, uts, and ipc namespaces,
applies Landlock, installs seccomp-bpf, and sets `no_new_privs`. It composes
with `libholdfast.so` so policy and a human still gate `open` / `exec` /
`connect`. The Apache-licensed CLI talks to it through `holdfast jail` and
`holdfast swarm`. If the binary is missing, those commands refuse to start.

Official source trees include this directory. Do not replace it with a stub
that skips isolation.

## Build

```bash
make
# → ./holdfast-jail
```

## Run

Prefer the operator CLI (sets session, socket, and preload for you):

```bash
holdfast jail -- python3 demo/swarm_probe.py
holdfast swarm --count 3 --net none -- python3 demo/swarm_probe.py
```

Direct:

```bash
./holdfast-jail --no-preload -- python3 demo/swarm_probe.py
./holdfast-jail --help
```

`--net host` (default) keeps host networking so the daemon socket and the
human gate still see `connect`. `--net none` is a network namespace: TCP to
the world fails; the filesystem Unix socket still works.

## What it closes

`LD_PRELOAD` wraps libc. Jail wraps the kernel view:

- **Mount + Landlock.** `/etc/shadow`, `/root`, and `$HOME` are not in the
  tree. Workspace is bind-mounted read-write. `/usr` is read-only.
- **PID + UTS.** Each member is pid 1 in its own namespace (`holdfast-N`).
- **seccomp.** `ptrace`, `bpf`, `mount`, `unshare`, `clone` with new
  namespaces, `io_uring`, and related escape hatches are denied or killed.
- **no_new_privs** and dropped capabilities after setup.

Raw syscalls still cannot see files that are not mounted. Static and Go
binaries are in the same namespace as a Python agent.

## License

Copyright 2026 Holdfast. Proprietary. See [LICENSE](LICENSE).
