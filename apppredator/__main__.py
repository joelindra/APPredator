"""Allow ``python -m apppredator`` (same as ``python -m apppredator.cli``)."""

from __future__ import annotations

if __name__ == "__main__":
    from apppredator.cli import main

    main()
