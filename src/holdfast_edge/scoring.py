"""Combine signal scores. Behavior dominates; tool-shape is a small bonus."""

from __future__ import annotations

from holdfast_edge.config import EdgeConfig

BEHAVIOR = ("burst", "fanout", "retry_loop", "goal_loop")
RULE_IDS = {
    "burst": "edge.burst",
    "fanout": "edge.fanout",
    "retry_loop": "edge.retry_loop",
    "goal_loop": "edge.goal_loop",
    "tool_client": "edge.tool_client",
}


def noisy_or(signals: dict[str, float], cfg: EdgeConfig) -> float:
    product = 1.0
    for name in BEHAVIOR:
        weight = getattr(cfg.weights, name)
        p = min(1.0, max(0.0, (signals.get(name, 0.0) / 100.0) * weight))
        product *= 1.0 - p
    combined = 100.0 * (1.0 - product)
    tool = min(cfg.bars.tool_client_max, max(0.0, signals.get("tool_client", 0.0)))
    bonus = min(10.0, tool * 0.4)
    return round(min(100.0, combined + bonus), 3)


def dominant_signal(signals: dict[str, float]) -> str | None:
    ranked = sorted(
        ((name, signals.get(name, 0.0)) for name in BEHAVIOR),
        key=lambda kv: kv[1],
        reverse=True,
    )
    if not ranked or ranked[0][1] < 15.0:
        return None
    return ranked[0][0]


def reason_for(signal: str | None, score: float, signals: dict[str, float]) -> str:
    if signal is None or score < 1.0:
        return "no swarm behavior above the floor"
    value = signals.get(signal, 0.0)
    labels = {
        "burst": "burst of requests from one client",
        "fanout": "fan-out across many paths from one client",
        "retry_loop": "tight retry loop on one path",
        "goal_loop": "goal-seeking path walk",
    }
    return f"{labels.get(signal, signal)} (signal {value:.1f}, combined {score:.1f})"
