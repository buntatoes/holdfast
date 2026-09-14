"""v0 signals: burst, fan-out, retry loops, tool-shaped clients, goal-seeking loops.

None of these score a User-Agent string as 'looks like GPT'. Tool-shape looks at
header *names* only (browser-like completeness), and is capped so it cannot
challenge or deny on its own.
"""

from __future__ import annotations

from holdfast_edge.config import EdgeConfig
from holdfast_edge.store import Snapshot

BROWSERISH = (
    "accept-language",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-ch-ua",
    "referer",
    "cookie",
)


def _ramp(count: float, bar: float) -> float:
    """0 at 0; 50 at the bar; 100 at 2x the bar."""
    if bar <= 0:
        return 0.0
    return max(0.0, min(100.0, 50.0 * (count / bar)))


def burst_score(snap: Snapshot, cfg: EdgeConfig) -> float:
    return _ramp(snap.burst_count, cfg.bars.burst_requests)


def fanout_score(snap: Snapshot, cfg: EdgeConfig) -> float:
    return _ramp(snap.distinct_paths, cfg.bars.fanout_distinct_paths)


def retry_score(snap: Snapshot, cfg: EdgeConfig) -> float:
    return _ramp(snap.retry_count, cfg.bars.retry_repeats)


def goal_score(snap: Snapshot, cfg: EdgeConfig) -> float:
    walk = _ramp(snap.numeric_id_walk, cfg.bars.goal_sequence_hits)
    spray = _ramp(snap.sensitive_families, cfg.bars.goal_sensitive_families)
    return max(walk, spray)


def tool_client_score(snap: Snapshot, cfg: EdgeConfig) -> float:
    names = {n.lower() for n in snap.header_names}
    if not names:
        return 0.0
    missing = sum(1 for key in BROWSERISH if key not in names)
    frac = missing / len(BROWSERISH)
    return min(cfg.bars.tool_client_max, cfg.bars.tool_client_max * frac)


def compute(snap: Snapshot, cfg: EdgeConfig) -> dict[str, float]:
    return {
        "burst": round(burst_score(snap, cfg), 3),
        "fanout": round(fanout_score(snap, cfg), 3),
        "retry_loop": round(retry_score(snap, cfg), 3),
        "goal_loop": round(goal_score(snap, cfg), 3),
        "tool_client": round(tool_client_score(snap, cfg), 3),
    }
