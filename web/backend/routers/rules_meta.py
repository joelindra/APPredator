from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter

from core.config_loader import load_settings
router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules_meta() -> dict[str, Any]:
    s = load_settings()
    rules_state = s.rules.model_dump()
    out = []
    vuln_dir = Path("config/prompts/vuln_rules")
    for name, enabled in rules_state.items():
        desc = ""
        yaml_path = vuln_dir / f"{name}.yaml"
        if yaml_path.is_file():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    d = yaml.safe_load(f) or {}
                desc = (d.get("description") or d.get("name") or "")[:300]
            except Exception:
                pass
        out.append({"id": name, "enabled": enabled, "description": desc})
    return {"rules": out}
