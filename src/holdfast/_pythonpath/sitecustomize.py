"""Loaded under `holdfast wrap` via sitecustomize.

glibc posix_spawn/vfork shares VM with the parent until exec. The child's
symbol binding rewrites the agent's PLT, so later connect() calls skip
libholdfast. Python 3.12 defaults to posix_spawn; turn that off when we
are the preload parent.
"""

from __future__ import annotations

import os


def _patch() -> None:
    if not os.environ.get("HOLDFAST_SOCK"):
        return
    try:
        import subprocess

        subprocess._USE_POSIX_SPAWN = False
        subprocess._USE_VFORK = False
    except Exception:
        pass


_patch()
