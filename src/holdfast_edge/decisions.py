"""Map a combined score to allow | challenge | deny.

Safety rails (Bastion):
- never silent hard-ban on first hit
- uncertain → challenge, not block
- deny only when score *and* observation count clear the bar
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from holdfast_edge.config import EdgeConfig
from holdfast_edge.scoring import RULE_IDS, dominant_signal, reason_for
from holdfast_edge.store import Snapshot

Action = Literal["allow", "challenge", "deny"]


@dataclass
class Decision:
    action: Action
    applied: Action
    score: float
    rule_id: str
    reason: str
    observed_at: str
    client_fp: str
    path_fp: str
    signals: dict[str, float] = field(default_factory=dict)
    observations: int = 0
    mode: str = "shadow"
    allowlisted: bool = False

    def as_public(self) -> dict[str, Any]:
        """What a client may see. No score, no fingerprints, no reasons."""
        if self.applied == "challenge":
            return {"error": "challenge", "challenge_id": self.observed_at}
        if self.applied == "deny":
            return {"error": "denied"}
        return {"ok": True}

    def as_operator(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "applied": self.applied,
            "score": self.score,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "observed_at": self.observed_at,
            "client_fp": self.client_fp,
            "path_fp": self.path_fp,
            "signals": self.signals,
            "observations": self.observations,
            "mode": self.mode,
            "allowlisted": self.allowlisted,
        }


def intended_action(
    score: float,
    snap: Snapshot,
    cfg: EdgeConfig,
    now: float,
) -> tuple[Action, str]:
    """Return (action, rail_note). Rails can only downgrade deny → challenge."""
    if score < cfg.thresholds.challenge:
        return "allow", ""
    if score < cfg.thresholds.deny:
        return "challenge", "uncertain: challenge not block"
    if snap.observations < cfg.thresholds.min_observations_before_deny:
        return "challenge", "first-hit: challenge not deny"
    lived = now - snap.first_seen
    if lived < cfg.thresholds.min_window_s_before_deny:
        return "challenge", "short window: challenge not deny"
    return "deny", ""


def decide(
    *,
    score: float,
    signals: dict[str, float],
    snap: Snapshot,
    cfg: EdgeConfig,
    now: float,
    observed_at: str,
    path_fp: str,
) -> Decision:
    action, rail = intended_action(score, snap, cfg, now)
    signal = dominant_signal(signals)
    if action == "allow":
        rule_id = "edge.allow"
    elif signal:
        rule_id = RULE_IDS[signal]
    else:
        rule_id = "edge.uncertain"
    reason = reason_for(signal, score, signals)
    if rail:
        reason = f"{rail}; {reason}"
    applied: Action = "allow" if cfg.is_shadow() else action
    return Decision(
        action=action,
        applied=applied,
        score=score,
        rule_id=rule_id,
        reason=reason,
        observed_at=observed_at,
        client_fp=snap.client_fp,
        path_fp=path_fp,
        signals=signals,
        observations=snap.observations,
        mode=cfg.mode,
    )
