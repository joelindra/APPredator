from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


DEFAULT_CACHE_PATH = Path(os.environ.get("APPREDATOR_CACHE_PATH", "output/.cache/cache.json"))


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class CacheStore:
    def __init__(self, path: Path = DEFAULT_CACHE_PATH):
        self.path = path
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"decompile": {}, "llm": {}}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d, dict):
                return {"decompile": {}, "llm": {}}
            d.setdefault("decompile", {})
            d.setdefault("llm", {})
            return d
        except Exception:
            return {"decompile": {}, "llm": {}}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def llm_get(self, key: str) -> str | None:
        v = self.data.get("llm", {}).get(key)
        if isinstance(v, str):
            return v
        return None

    def llm_put(self, key: str, value: str) -> None:
        self.data.setdefault("llm", {})[key] = value

    def decompile_get(self, key: str) -> dict[str, Any] | None:
        v = self.data.get("decompile", {}).get(key)
        if isinstance(v, dict):
            return v
        return None

    def decompile_put(self, key: str, value: dict[str, Any]) -> None:
        self.data.setdefault("decompile", {})[key] = value

    def cleanup(self, max_llm: int = 5000) -> None:
        llm = self.data.get("llm", {})
        if isinstance(llm, dict) and len(llm) > max_llm:
            keys = list(llm.keys())[-max_llm:]
            self.data["llm"] = {k: llm[k] for k in keys}
