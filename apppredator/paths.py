from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache
def project_root() -> Path:
    """
    Repository root (directory that contains ``config/``, ``core/``, ``web/``).

    Resolved from this package location so CLI, ``uvicorn``, and tests behave
    the same regardless of current working directory.
    """
    return Path(__file__).resolve().parent.parent
