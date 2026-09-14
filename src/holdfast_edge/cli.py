"""Holdfast Edge operator CLI. Separate binary from `holdfast` / `holdfastd`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import URLError
from urllib.request import urlopen


def _base(cfg_port: int | None = None) -> str:
    env = os.environ.get("HOLDFAST_EDGE_HTTP")
    if env:
        return env.rstrip("/")
    port = cfg_port or int(os.environ.get("HOLDFAST_EDGE_HTTP_PORT") or 47831)
    host = os.environ.get("HOLDFAST_EDGE_HTTP_HOST") or "127.0.0.1"
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    return f"http://{host}:{port}"


def cmd_serve(_args: argparse.Namespace) -> int:
    from holdfast_edge.server import main as server_main

    server_main()
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    import uvicorn

    from holdfast_edge.config import load as load_cfg
    from holdfast_edge.engine import EdgeEngine
    from holdfast_edge.proxy import build_proxy

    cfg = load_cfg()
    if args.mode:
        cfg = cfg.with_mode(args.mode)
    engine = EdgeEngine(cfg)
    app = build_proxy(args.origin, engine=engine)
    uvicorn.run(app, host=cfg.listen_host, port=cfg.listen_port, log_level="info")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    url = _base() + "/health"
    try:
        with urlopen(url, timeout=3) as resp:
            sys.stdout.write(resp.read().decode("utf-8") + "\n")
            return 0
    except URLError as exc:
        print(f"holdfast-edge status: unreachable at {url}: {exc}", file=sys.stderr)
        return 1


def cmd_provenance(args: argparse.Namespace) -> int:
    url = _base() + f"/v1/provenance?limit={int(args.limit)}"
    try:
        with urlopen(url, timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"holdfast-edge provenance: {exc}", file=sys.stderr)
        return 1
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="holdfast-edge",
        description="Holdfast Edge. Score swarm behavior in front of a website.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the observe API")
    serve.set_defaults(func=cmd_serve)

    proxy = sub.add_parser("proxy", help="reverse-proxy an origin through Edge")
    proxy.add_argument("--origin", required=True, help="upstream origin, e.g. http://127.0.0.1:8080")
    proxy.add_argument("--mode", choices=["shadow", "enforce"], help="override policy mode")
    proxy.set_defaults(func=cmd_proxy)

    status = sub.add_parser("status", help="GET /health")
    status.set_defaults(func=cmd_status)

    prov = sub.add_parser("provenance", help="print recent operator provenance")
    prov.add_argument("--limit", type=int, default=50)
    prov.set_defaults(func=cmd_provenance)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
