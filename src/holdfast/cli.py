"""Holdfast operator CLI: wrap, status, audit, demo, serve."""

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
    env = os.environ.copy()
    existing = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = f"{lib}:{existing}" if existing else str(lib)
    env["HOLDFAST_SOCK"] = env.get("HOLDFAST_SOCK") or sock_path()
    env["HOLDFAST_SESSION"] = env.get("HOLDFAST_SESSION") or str(uuid.uuid4())
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("LD_BIND_NOW", "1")
    patch_dir = Path(__file__).resolve().parent / "_pythonpath"
    if patch_dir.is_dir():
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            str(patch_dir) if not existing_pp else f"{patch_dir}{os.pathsep}{existing_pp}"
        )
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


def jail_exec(
    argv: list[str],
    *,
    swarm: str | None = None,
    agent: str | None = None,
    workspace: str | None = None,
    isolate_net: bool = False,
    ro_root: bool = False,
    wrap: bool = True,
    verbose: bool = False,
) -> int:
    argv = _wrap_argv(argv)
    if not argv:
        print("holdfast jail: missing command after --", file=sys.stderr)
        return 2
    jail_bin = find_jail_bin()
    if not jail_bin.is_file():
        print(
            f"holdfast jail: jail binary not found at {jail_bin}. "
            "Build it with `make -C jail` (fail-closed: refusing to run unjailed).",
            file=sys.stderr,
        )
        return 2

    jail_cmd = [str(jail_bin)]
    if swarm:
        jail_cmd.extend(["--swarm", swarm])
    if agent:
        jail_cmd.extend(["--agent", agent])
    if workspace:
        jail_cmd.extend(["--workspace", workspace])
    if isolate_net:
        jail_cmd.append("--isolate-net")
    if ro_root:
        jail_cmd.append("--ro-root")
    if verbose:
        jail_cmd.append("--verbose")
    jail_cmd.append("--")

    if wrap:
        # Wrap the target command inside the jail with LD_PRELOAD
        lib = find_preload_lib()
        if not lib.is_file():
            print(
                f"holdfast jail: preload library not found at {lib}. "
                "Build it with `make -C preload` (fail-closed: refusing to exec unwrapped).",
                file=sys.stderr,
            )
            return 2
        env = os.environ.copy()
        existing = env.get("LD_PRELOAD", "")
        env["LD_PRELOAD"] = f"{lib}:{existing}" if existing else str(lib)
        env["HOLDFAST_SOCK"] = env.get("HOLDFAST_SOCK") or sock_path()
        session_id = f"{swarm}:{agent}" if (swarm and agent) else (agent or swarm or str(uuid.uuid4()))
        env["HOLDFAST_SESSION"] = env.get("HOLDFAST_SESSION") or session_id
        env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.setdefault("LD_BIND_NOW", "1")
        patch_dir = Path(__file__).resolve().parent / "_pythonpath"
        if patch_dir.is_dir():
            existing_pp = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                str(patch_dir) if not existing_pp else f"{patch_dir}{os.pathsep}{existing_pp}"
            )
    else:
        env = os.environ.copy()

    full_argv = [*jail_cmd, *argv]
    prog = full_argv[0]
    try:
        os.execvpe(prog, full_argv, env)
    except OSError as exc:
        print(f"holdfast jail: failed to exec {prog}: {exc}", file=sys.stderr)
        return 127
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    return wrap_exec(list(args.argv))


def cmd_jail(args: argparse.Namespace) -> int:
    return jail_exec(
        list(args.argv),
        swarm=args.swarm,
        agent=args.agent,
        workspace=args.workspace,
        isolate_net=args.isolate_net,
        ro_root=args.ro_root,
        wrap=not args.no_wrap,
        verbose=args.verbose,
    )


def cmd_demo(_args: argparse.Namespace) -> int:
    script = find_demo_script()
    return wrap_exec(["python3", str(script)])


def cmd_jail_standalone() -> None:
    jail_bin = find_jail_bin()
    if not jail_bin.is_file():
        print(
            f"holdfast-jail: binary not found at {jail_bin}. Build with `make -C jail`.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    os.execv(str(jail_bin), [str(jail_bin), *sys.argv[1:]])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="holdfast",
        description="Holdfast operator CLI. Agents propose. You decide.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    wrap_p = sub.add_parser("wrap", help="exec a command under LD_PRELOAD")
    wrap_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="command to exec; use: holdfast wrap -- cmd...",
    )
    wrap_p.set_defaults(func=cmd_wrap)

    jail_p = sub.add_parser("jail", help="run command inside an isolated Linux namespace jail for agent swarms")
    jail_p.add_argument(
        "--swarm",
        default=None,
        help="swarm identifier for grouping agent instances",
    )
    jail_p.add_argument(
        "--agent",
        default=None,
        help="agent identifier within the swarm",
    )
    jail_p.add_argument(
        "--workspace",
        default=None,
        help="working directory for the jailed agent",
    )
    jail_p.add_argument(
        "--isolate-net",
        action="store_true",
        help="unshare network namespace to block host network access",
    )
    jail_p.add_argument(
        "--ro-root",
        action="store_true",
        help="mount root filesystem read-only",
    )
    jail_p.add_argument(
        "--no-wrap",
        action="store_true",
        help="do not inject LD_PRELOAD enforcement into the jail",
    )
    jail_p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print jail setup diagnostics",
    )
    jail_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="command to exec in jail; use: holdfast jail [options] -- cmd...",
    )
    jail_p.set_defaults(func=cmd_jail)

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
