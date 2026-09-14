"""Holdfast Edge: sit in front of a website and score swarm behavior.

Separate from the host daemon. A bad edge rule cannot brick `holdfast wrap`.
Agents propose. Humans and policy verify.
"""

from __future__ import annotations

__version__ = "0.2.0"

from holdfast_edge.decisions import Decision
from holdfast_edge.engine import EdgeEngine
from holdfast_edge.config import EdgeConfig

__all__ = ["__version__", "Decision", "EdgeEngine", "EdgeConfig"]
