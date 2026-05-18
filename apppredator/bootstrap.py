from __future__ import annotations

import os
from pathlib import Path

from apppredator.paths import project_root


def configure_runtime(*, mkdirs: bool = True) -> Path:
    """
    Pin process state to the project root (``config/``, ``output/``, relative assets).

    Call from CLI import time and from the API lifespan so paths stay consistent.
    """
    import sys
    # For Windows consoles, enforce UTF-8 encoding to prevent charmap/Unicode rendering crashes
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except AttributeError:
            pass  # Fallback for Python versions lacking reconfigure

    root = project_root()
    os.chdir(root)
    if mkdirs:
        Path("output").mkdir(exist_ok=True)
        Path("web_data").mkdir(exist_ok=True)
    return root
