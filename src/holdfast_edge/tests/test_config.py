from __future__ import annotations

from pathlib import Path

from holdfast_edge.config import from_dict, load_yaml


def test_shipped_yaml_is_shadow() -> None:
    path = Path(__file__).resolve().parents[3] / "policies" / "edge.yaml"
    assert path.is_file()
    cfg = load_yaml(path)
    assert cfg.mode == "shadow"
    assert cfg.listen_port == 47831
    assert cfg.thresholds.challenge < cfg.thresholds.deny
    assert cfg.thresholds.min_observations_before_deny >= 1
    assert "/health" in cfg.allowlist.path_prefixes


def test_dry_run_alias() -> None:
    assert from_dict({"mode": "dry_run"}).mode == "shadow"
    assert from_dict({"mode": "dry-run"}).mode == "shadow"
    assert from_dict({"mode": "enforce"}).mode == "enforce"
