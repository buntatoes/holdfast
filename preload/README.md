# libholdfast.so

Linux `LD_PRELOAD` interceptor for Holdfast. It wraps libc file, shell, and
network entry points and asks the daemon over `$HOLDFAST_SOCK` before the
real call proceeds. Missing socket, timeout (300s), or a non-`allow`
response: the call fails with `EPERM` (fail-closed).

## Build

From this directory:

```bash
make
# equivalent: gcc -shared -fPIC -O2 -ldl -o libholdfast.so holdfast_preload.c
```

That writes `./libholdfast.so`. `make install` copies the same file to
`/workspace/preload/libholdfast.so`.

## Run under Holdfast

Point the process at the library and the daemon socket:

```bash
LD_PRELOAD=./libholdfast.so HOLDFAST_SOCK=/tmp/holdfast.sock HOLDFAST_SESSION=dev -- \
  your-command
```

Typical usage (same directory as the `.so`):

```bash
LD_PRELOAD=./libholdfast.so HOLDFAST_SOCK=/tmp/holdfast.sock ls /
```

`holdfast wrap -- <cmd...>` sets `LD_PRELOAD`, `HOLDFAST_SOCK`, and
`HOLDFAST_SESSION` for you.

Environment:

| Variable | Role |
| --- | --- |
| `LD_PRELOAD` | Path to `libholdfast.so` |
| `HOLDFAST_SOCK` | Unix socket path (default `/tmp/holdfast.sock`) |
| `HOLDFAST_SESSION` | Session id sent on every request (empty if unset) |

The library talks newline-delimited JSON on that socket (see `PROTOCOL.md`).
IPC uses `dlsym(RTLD_NEXT)` for `socket` / `connect` / `write` / `read` /
`close` plus a thread-local re-entrancy guard so the library does not
intercept its own traffic. Connects and opens of `$HOLDFAST_SOCK` itself
are skipped so the channel stays up.

## Test fail-closed (no daemon)

If nothing is listening, every gated call is denied:

```bash
LD_PRELOAD=./libholdfast.so HOLDFAST_SOCK=/tmp/holdfast.sock \
  python3 -c 'open("/etc/passwd")'
# PermissionError: [Errno 1] Operation not permitted
```

Same for `exec` and `connect`.

## Test with a throwaway allow-all socket

A one-shot listener that always answers `allow` (not the real daemon):

```bash
python3 - <<'PY' &
import json, os, socket, threading
path = "/tmp/holdfast.sock"
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(32)

def handle(c):
    with c:
        buf = b""
        while b"\n" not in buf:
            chunk = c.recv(4096)
            if not chunk:
                return
            buf += chunk
        line = buf.split(b"\n", 1)[0]
        req = json.loads(line.decode())
        c.sendall((json.dumps({"id": req["id"], "decision": "allow"}) + "\n").encode())

while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY

LD_PRELOAD=./libholdfast.so HOLDFAST_SOCK=/tmp/holdfast.sock cat /etc/passwd | head
```

## Intercepted symbols

- **file:** `open`, `open64`, `openat`, `openat64`, `creat`, `unlink`,
  `unlinkat`, `rename`, `renameat`, `fopen`, `fopen64`
- **shell:** `execve`, `execv`, `execvp`, `execvpe`, `execveat`
  (`system` / `popen` / Python `subprocess` go through these)
- **vfork:** implemented as `fork`, so `posix_spawn` cannot rewrite the
  parent PLT (see README limitations)
- **net:** `connect`

Relative paths are resolved against the process cwd (or `dirfd` for `*at`)
before they are sent. `open` flags become `r` / `w` / `rw` as in the
protocol (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` count as write).
