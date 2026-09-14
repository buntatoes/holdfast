# Holdfast Jail

**Kernel isolation for agent swarms. Proprietary. Official builds include it.**

Holdfast Jail is the kernel cut of Holdfast. The host daemon and `LD_PRELOAD`
gate still decide `open` / `exec` / `connect`. Jail puts each agent in Linux
namespaces, Landlock, and seccomp so raw syscalls, static binaries, and Go
agents share that isolation.

This is **not** Apache-2.0. See `jail/LICENSE`. The rest of Holdfast stays
Apache-2.0. `holdfast wrap` remains the libc gate. `holdfast jail` and
`holdfast swarm` refuse to start if the Jail binary is missing.

Agents propose. Humans and policy verify. Jail does not read the prompt.

## What it does

Each jailed process gets:

| Layer | Effect |
| --- | --- |
| User + mount + pid + uts + ipc namespaces | Own pid 1, own hostname, own `/proc`, no `/root` or `$HOME` |
| Landlock | Deny-by-default filesystem; workspace and `/tmp` are read-write; `/usr` and `/etc` (no shadow) are read-only |
| seccomp-bpf | `ptrace`, `bpf`, `unshare`, `mount`, namespace `clone`, `io_uring`, and related escapes are denied or killed |
| `no_new_privs` + dropped capabilities | After setup, the agent cannot regain privilege |

`--net host` (default) keeps host networking so the human gate still sees
`connect`. `--net none` is a network namespace: TCP to the world fails.

Swarm members share the workspace bind and the daemon socket. They do not
share pid namespaces or `/tmp`.

## What it does not do

- It does not replace policy or the operator desk. Writes, exec, and connect
  still `ask` unless policy already decided.
- It is not a VM or a multi-tenant control plane.
- `--net host` is not IP isolation. Use `--net none` when the swarm must not
  speak TCP.
- A bind of `--root` that includes secrets is still a bind of those secrets.

## Run

```bash
make -C jail                 # → jail/holdfast-jail
holdfastd                    # daemon, as with wrap
holdfast jail -- python3 demo/swarm_probe.py
holdfast swarm --count 3 --net none -- python3 demo/swarm_probe.py
holdfast wrap --jail -- python3 demo/naughty_agent.py
```

Direct (same binary):

```bash
./jail/holdfast-jail --help
./jail/holdfast-jail --no-preload -- python3 demo/swarm_probe.py
```

Environment: `HOLDFAST_SOCK`, `HOLDFAST_SESSION`, `HOLDFAST_JAIL_BIN`.
Inside the jail: `HOLDFAST_JAIL=1`, `HOLDFAST_JAIL_MEMBER` (swarm).

## Privacy

Jail does not import host identity:

- `/etc/passwd` and `/etc/group` inside the jail are synthetic (`root` and
  `nobody`). Host usernames and `/home/...` paths are not copied in.
- `/etc/hosts` and `/etc/hostname` are written for the jail hostname
  (`holdfast` or `holdfast-N`), not the host's name.
- `/root` and `/home` are not mounted. `/etc/shadow` is not mounted.
- The operator audit log still records what the agent *proposed* (path,
  argv, host:port). That log stays on the operator machine.

A `--root` bind of a checkout that contains secrets is still a bind of those
secrets. Keep the workspace to the repo.

## License

Copyright 2026 Holdfast. Proprietary. See `jail/LICENSE` and `NOTICE`.
Earlier Holdfast versions (0.2.1 and before) remain under their original
licenses and do not include Jail.
