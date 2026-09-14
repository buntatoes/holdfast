# Holdfast Edge

**Sit in front of a website. Score swarm behavior. Challenge before you block.**

Holdfast Edge is a second mode of Holdfast. The host daemon still gates an agent process with `LD_PRELOAD`. Edge sits in front of a website and watches how clients behave: bursts, fan-out across many paths, retry loops, goal-seeking walks.

Agents propose. Humans and policy verify. Edge does not try to guess who wrote the client. It scores what the client *does*.

This package is separate from the host daemon on purpose. A bad edge rule cannot brick `holdfast wrap`.

## What it does

Every request is fingerprinted (hashed; raw IP and User-Agent are dropped), then scored.

| Decision | When |
| --- | --- |
| **allow** | Score is below the challenge bar, or the request matches an allowlist. |
| **challenge** | Score is in the middle band, or the score is high but this is a first hit / short window. |
| **deny** | Score clears the deny bar *and* enough observations have piled up. |

Uncertain traffic is challenged, not blocked. A first request is never a silent ban.

Start in **shadow** mode. Edge logs what it would do and lets every request through. Turn on **enforce** only after the log looks right.

## What it does not do

- It does not ban on “looks like an AI” User-Agent strings. A claimed bot name, by itself, is not a signal.
- It does not read request bodies. It does not keep query values, emails, or raw IPs. Provenance stores hashes and redacted path patterns.
- It does not share process space or policy files with the host wrap path.
- It is fail-**open** on internal errors. False-positive denial of service is the number one risk. (The host daemon is still fail-closed. Different job.)

## Signals (v0)

| Signal | Looks for |
| --- | --- |
| `edge.burst` | Too many requests from one client in a short window. |
| `edge.fanout` | One client hitting many distinct paths quickly. |
| `edge.retry_loop` | The same path, over and over, tight cadence. |
| `edge.goal_loop` | Numeric id walking (`/users/1`, `/users/2`, …) or spraying admin/login/env-style paths. |
| `edge.tool_client` | Header *names* that look like a script, not a browser. Capped. Cannot challenge or deny alone. |

Scores combine with a noisy-OR of the behavior signals. Tool-shape may add a little corroboration. It cannot push a quiet client over the bar.

## Modes

- **shadow** (default, also called dry-run): compute a decision, write provenance, **apply allow**.
- **enforce**: apply the decision. Challenge returns HTTP 429. Deny returns HTTP 403. The client body does not include score or reason (that is operator-only).

## Allowlists

Allowlists run first and always allow. Use them for health checks, static assets, office networks, and an operator token.

A prefix matches that path and its children only. `/health` matches `/health` and `/health/live`, not `/healthcare`. Paths are normalized first, so `/health/../admin` is treated as `/admin` and is not allowlisted.

```yaml
allowlist:
  path_prefixes: ["/health", "/assets/", "/static/"]
  cidrs: ["198.51.100.0/24"]
  header_tokens: ["…"]
```

## Provenance

Every scored request writes an operator record: `reason`, `score`, `rule_id`, `observed_at`, plus the hashed client and path fingerprints and the per-signal breakdown.

Deny records must include those four fields. Retention is short (24 hours by default). This log is operational, not the host daemon’s append-only audit chain, and it is pruned on purpose.

## Run

Edge listens on `127.0.0.1:47831` so it cannot collide with the host daemon on `:47821`.

```bash
# Observe API (middleware-shaped). Default mode is shadow.
holdfast-edge serve

# Reverse-proxy an origin. Stay in shadow until the log looks right.
holdfast-edge proxy --origin http://127.0.0.1:8080 --mode shadow

# After you have watched it:
holdfast-edge proxy --origin http://127.0.0.1:8080 --mode enforce

holdfast-edge status
holdfast-edge provenance
```

Observe API:

- `POST /v1/observe` — send request metadata, get a decision
- `GET /health`
- `GET /v1/config` — thresholds and mode (no secrets)
- `GET /v1/provenance?limit=100`

ASGI middleware (`holdfast_edge.middleware.EdgeMiddleware`) wraps any Starlette/FastAPI app the same way.

Policy file: `policies/edge.yaml`. Override with `HOLDFAST_EDGE_POLICY`, `HOLDFAST_EDGE_MODE`, `HOLDFAST_EDGE_SALT`.

Set `HOLDFAST_EDGE_SALT` in real deploys. An empty salt is weaker — fingerprints are easier to reverse.

Behind a CDN or proxy, pass the real client IP into Edge. If every request looks like the proxy, scores attach to the wrong face.

Scores live in one process. There is no shared store yet. A restart or a second replica starts a fresh slate.

Caller-supplied client ids are hashed the same way as IPs. Raw IPs never land in provenance.

## Ship bar

Challenge or deny only when the score clears a bar. Uncertain → challenge, not block. Shadow first, enforce second. Tunable thresholds. Provenance on every deny. No full bodies. Separate package from wrap.
