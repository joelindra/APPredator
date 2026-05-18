from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.config_loader import load_settings
from core.settings_io import (
    DEFAULT_SETTINGS_PATH,
    load_settings_tree,
    merge_dict_into_tree,
    save_settings_tree,
    tree_to_plain,
)
router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsPutBody(BaseModel):
    """Partial or full settings object merged into existing YAML."""

    data: dict[str, Any]


@router.get("")
def get_settings() -> dict[str, Any]:
    tree = load_settings_tree()
    return {"path": str(DEFAULT_SETTINGS_PATH), "data": tree_to_plain(tree)}


@router.put("")
def put_settings(body: SettingsPutBody) -> dict[str, Any]:
    tree = load_settings_tree()
    if not tree:
        tree = {}
    merge_dict_into_tree(tree, body.data)
    save_settings_tree(tree)
    try:
        load_settings()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid settings after merge: {e}") from e
    return {"ok": True, "path": str(DEFAULT_SETTINGS_PATH)}


@router.get("/validate")
def validate_settings() -> dict[str, Any]:
    try:
        s = load_settings()
        return {"valid": True, "summary": s.model_dump()}
    except Exception as e:
        return {"valid": False, "error": str(e)}
