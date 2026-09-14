"""Holdfast operator CLI: wrap, jail, swarm, status, audit, demo, serve."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from holdfast.audit import AuditLog
from holdfast.util import (
    HTTP_BASE,
    default_audit_path,
    find_jail_bin,
    find_preload_lib,
    sock_path,
)


def cmd_serve(_args: argparse.Namespace) -> int:
    from holdfast.server import main as server_main

    server_main()
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    url = os.environ.get("HOLDFAST_HTTP", HTTP_BASE) + "/health"
    try:
        with urlopen(url, timeout=3) as resp:
            body = resp.read().decode("utf-8")
            print(body if body.endswith("\n") else body + "\n", end="")
            return 0
    except URLError as exc:
        print(f"holdfast status: daemon unreachable at {url}: {exc}", file=sys.stderr)
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    path = default_audit_path()
    env_url = os.environ.get("HOLDFAST_HTTP", HTTP_BASE)
    items = None
    try:
        with urlopen(f"{env_url}/api/audit?limit=50", timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            items = payload.get("items") or []
    except (URLError, json.JSONDecodeError, TimeoutError):
        log = AuditLog.open(path)
        items = log.tail(50)
    if args.json:
        json.dump({"items": items}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if not items:
        print("no audit events")
        return 0
    for rec in items:
        ts = rec.get("ts", "")
        decision = rec.get("decision", "")
        actor = rec.get("actor", "")
        kind = rec.get("kind", "")
        op = rec.get("op", "")
        detail = rec.get("detail") or {}
        target = (
            detail.get("path")
            or " ".join(str(x) for x in (detail.get("argv") or [])[:6])
            or (
                f"{detail.get('host')}:{detail.get('port')}"
                if detail.get("host") is not None
                else ""
            )
        )
        print(f"{ts}  {decision:5}  {actor:24}  {kind}/{op}  {target}")
    return 0


def _wrap_argv(argv: list[str]) -> list[str]:
    cleaned = list(argv)
    if cleaned and cleaned[0] == "--":
        cleaned = cleaned[1:]
    return cleaned


def find_demo_script() -> Path:
    candidates = [
        Path("/workspace/demo/naughty_agent.py"),
        Path.cwd() / "demo" / "naughty_agent.py",
        Path(__file__).resolve().parents[2] / "demo" / "naughty_agent.py",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def _agent_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("LD_BIND_NOW", "1")
    patch_dir = Path(__file__).resolve().parent / "_pythonpath"
    if patch_dir.is_dir():
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(patch_dir) if not existing_pp else f"{patch_dir}{os.pathsep}{existing_pp}"
        )
    return env


def jail_command_argv(
    argv: list[str],
    *,
    member: int | None = None,
    net: str = "host",
    no_preload: bool = False,
    root: str | None = None,
    session: str | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build argv+env for the proprietary holdfast-jail supervisor."""
    argv = _wrap_argv(argv)
    if not argv:
        raise ValueError("missing command after --")
    jail = find_jail_bin()
    if not jail.is_file():
        raise FileNotFoundError(
            f"holdfast-jail not found at {jail}. "
            "Build it with `make -C jail` (fail-closed: refusing to exec unjailed)."
        )
    cmd = [str(jail)]
    lib = find_preload_lib()
    if no_preload:
        cmd.append("--no-preload")
    elif lib.is_file():
        cmd.extend(["--preload", str(lib)])
    else:
        cmd.append("--no-preload")
    cmd.extend(["--sock", os.environ.get("HOLDFAST_SOCK") or sock_path()])
    sess = session or os.environ.get("HOLDFAST_SESSION") or str(uuid.uuid4())
    if member is not None:
        cmd.extend(["--member", str(member)])
        cmd.extend(["--session", f"{sess}-m{member}"])
    else:
        cmd.extend(["--session", sess])
    if net:
        cmd.extend(["--net", net])
    workspace = Path(root).resolve() if root else Path.cwd().resolve()
    cmd.extend(["--root", str(workspace)])
    cmd.append("--")
    cmd.extend(argv)
    return cmd, _agent_env()


def jail_exec(
    argv: list[str],
    *,
    member: int | None = None,
    net: str = "host",
    no_preload: bool = False,
    root: str | None = None,
    session: str | None = None,
) -> int:
    try:
        cmd, env = jail_command_argv(
            argv,
            member=member,
            net=net,
            no_preload=no_preload,
            root=root,
            session=session,
        )
    except ValueError as exc:
        print(f"holdfast jail: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as exc:
        print(f"holdfast jail: failed to exec {cmd[0]}: {exc}", file=sys.stderr)
        return 127
    return 0


def wrap_exec(argv: list[str]) -> int:
    argv = _wrap_argv(argv)
    if not argv:
        print("holdfast wrap: missing command after --", file=sys.stderr)
        return 2
    lib = find_preload_lib()
    if not lib.is_file():
        print(
            f"holdfast wrap: preload library not found at {lib}. "
            "Build it with `make -C preload` (fail-closed: refusing to exec unwrapped).",
            file=sys.stderr,
        )
        return 2
    env = _agent_env()
    existing = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = f"{lib}:{existing}" if existing else str(lib)
    env["HOLDFAST_SOCK"] = env.get("HOLDFAST_SOCK") or sock_path()
    env["HOLDFAST_SESSION"] = env.get("HOLDFAST_SESSION") or str(uuid.uuid4())
    prog = argv[0]
    resolved = shutil.which(prog) if os.path.sep not in prog else prog
    if resolved:
        argv = [resolved, *argv[1:]]
        prog = resolved
    try:
        os.execvpe(prog, argv, env)
    except OSError as exc:
        print(f"holdfast wrap: failed to exec {prog}: {exc}", file=sys.stderr)
        return 127
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    if getattr(args, "jail", False):
        return jail_exec(
            list(args.argv),
            net=getattr(args, "net", "host") or "host",
            no_preload=getattr(args, "no_preload", False),
        )
    return wrap_exec(list(args.argv))


def cmd_jail(args: argparse.Namespace) -> int:
    return jail_exec(
        list(args.argv),
        net=args.net,
        no_preload=args.no_preload,
        root=args.root,
    )


def cmd_swarm(args: argparse.Namespace) -> int:
    count = args.count
    if count < 1:
        print("holdfast swarm: --count must be >= 1", file=sys.stderr)
        return 2
    session = os.environ.get("HOLDFAST_SESSION") or str(uuid.uuid4())
    pids: list[int] = []
    try:
        for i in range(count):
            cmd, env = jail_command_argv(
                list(args.argv),
                member=i,
                net=args.net,
                no_preload=args.no_preload,
                root=args.root,
                session=session,
            )
            pid = os.fork()
            if pid == 0:
                try:
                    os.execvpe(cmd[0], cmd, env)
                except OSError as exc:
                    print(f"holdfast swarm: member {i} exec failed: {exc}", file=sys.stderr)
                    os._exit(127)
            pids.append(pid)
    except ValueError as exc:
        print(f"holdfast swarm: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    failed = 0
    for pid in pids:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            if os.WEXITSTATUS(status) != 0:
                failed += 1
        else:
            failed += 1
    if failed:
        print(f"holdfast swarm: {failed}/{count} members failed", file=sys.stderr)
        return 1
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    script = find_demo_script()
    return wrap_exec(["python3", str(script)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="holdfast",
        description="Holdfast operator CLI. Agents propose. You decide.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    wrap_p = sub.add_parser("wrap", help="exec a command under LD_PRELOAD")
    wrap_p.add_argument(
        "--jail",
        action="store_true",
        help="exec under proprietary holdfast-jail (kernel isolation + preload)",
    )
    wrap_p.add_argument(
        "--net",
        choices=["host", "none"],
        default="host",
        help="jail network mode when --jail is set (default: host)",
    )
    wrap_p.add_argument(
        "--no-preload",
        action="store_true",
        help="with --jail, skip LD_PRELOAD (kernel jail only)",
    )
    wrap_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="command to exec; use: holdfast wrap -- cmd...",
    )
    wrap_p.set_defaults(func=cmd_wrap)

    jail_p = sub.add_parser(
        "jail",
        help="exec a command in the proprietary kernel jail",
    )
    jail_p.add_argument(
        "--net",
        choices=["host", "none"],
        default="host",
        help="host keeps host net; none is a network namespace",
    )
    jail_p.add_argument(
        "--no-preload",
        action="store_true",
        help="kernel jail only; skip LD_PRELOAD",
    )
    jail_p.add_argument("--root", default=None, help="workspace bind (default: cwd)")
    jail_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="command to exec; use: holdfast jail -- cmd...",
    )
    jail_p.set_defaults(func=cmd_jail)

    swarm_p = sub.add_parser(
        "swarm",
        help="run N isolated jail members (proprietary holdfast-jail)",
    )
    swarm_p.add_argument(
        "--count",
        type=int,
        default=2,
        help="number of isolated members (default: 2)",
    )
    swarm_p.add_argument(
        "--net",
        choices=["host", "none"],
        default="host",
        help="host keeps host net; none is a network namespace per member",
    )
    swarm_p.add_argument(
        "--no-preload",
        action="store_true",
        help="kernel jail only; skip LD_PRELOAD",
    )
    swarm_p.add_argument("--root", default=None, help="shared workspace bind (default: cwd)")
    swarm_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="command each member execs; use: holdfast swarm --count 3 -- cmd...",
    )
    swarm_p.set_defaults(func=cmd_swarm)

    status_p = sub.add_parser("status", help="GET /health on the daemon")
    status_p.set_defaults(func=cmd_status)

    audit_p = sub.add_parser("audit", help="print last 50 audit events")
    audit_p.add_argument(
        "--json",
        action="store_true",
        help="print JSON {items: [...]} instead of a text table",
    )
    audit_p.set_defaults(func=cmd_audit)

    demo_p = sub.add_parser("demo", help="wrap python3 demo/naughty_agent.py")
    demo_p.set_defaults(func=cmd_demo)

    serve_p = sub.add_parser("serve", help="alias for holdfastd")
    serve_p.set_defaults(func=cmd_serve)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
