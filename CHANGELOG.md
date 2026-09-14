# Changelog

## 0.2.2

- Proprietary Holdfast Jail (`jail/`): Linux user/mount/pid/uts/ipc namespaces,
  Landlock, seccomp-bpf, `no_new_privs`. Not Apache-2.0; see `jail/LICENSE`.
- CLI: `holdfast jail`, `holdfast swarm --count N`, `holdfast wrap --jail`.
- `holdfast jail` / `holdfast swarm` refuse to start if `holdfast-jail` is missing.
- `GET /api/sessions` lists wrap/jail/swarm sessions.
- Demo: `demo/swarm_probe.py`. Operator notes: `JAIL.md`.

## 0.2.1

- Edge allowlist path percent-decode (including double-encoding).
- License: Apache-2.0 (was MIT in 0.2.0).

## 0.2.0

- Holdfast Edge: shadow/enforce scoring for swarm-like web traffic.
