"""
Round-trip read/write for config/settings.yaml using ruamel.yaml.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Optional

from ruamel.yaml import YAML


DEFAULT_SETTINGS_PATH = Path(os.environ.get("APPREDATOR_SETTINGS_PATH", "config/settings.yaml"))

# core/settings_io.py → parents[1] is repository root (where tools/, config/ live).
_REPO_ROOT = Path(__file__).resolve().parents[1]


def resolve_tool_path(path_str: str | None) -> str | None:
    """
    Turn settings paths like tools/apktool/foo.bat into absolute paths under the repo root.

    Relative paths with slashes fix Windows health checks: cmd.exe treats `/` in the first
    token as switches unless the path is absolute (typically backslashes after resolve()).
    """
    if path_str is None:
        return None
    s = str(path_str).strip()
    if not s:
        return None
    p = Path(s)
    if p.is_absolute():
        return str(p.resolve())
    looks_like_path = (os.sep in s) or ("/" in s) or ("\\" in s)
    if looks_like_path:
        cand = (_REPO_ROOT / p).resolve()
        if cand.is_file():
            return str(cand)
        if p.is_file():
            return str(p.resolve())
        return str(cand)
    if shutil.which(s):
        return s
    return s


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def load_settings_tree(path: Optional[Path] = None) -> Any:
    p = path or DEFAULT_SETTINGS_PATH
    if not p.is_file():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        data = _yaml().load(f)
    return data if data is not None else {}


def save_settings_tree(data: Any, path: Optional[Path] = None) -> None:
    p = path or DEFAULT_SETTINGS_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        _yaml().dump(data, f)


def merge_dict_into_tree(tree: Any, updates: dict[str, Any]) -> None:
    """In-place deep merge of updates into ruamel CommentedMap / dict."""

    def merge(dst: Any, src: dict[str, Any]) -> None:
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                merge(dst[k], v)
            else:
                dst[k] = v

    if tree is None:
        return
    merge(tree, updates)


def tree_to_plain(data: Any) -> dict[str, Any]:
    """Convert ruamel tree to plain dict for JSON serialization."""
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    if isinstance(data, CommentedMap):
        return {k: tree_to_plain(v) for k, v in data.items()}
    if isinstance(data, CommentedSeq):
        return [tree_to_plain(x) for x in data]
    if isinstance(data, dict):
        return {k: tree_to_plain(v) for k, v in data.items()}
    if isinstance(data, list):
        return [tree_to_plain(x) for x in data]
    return data
