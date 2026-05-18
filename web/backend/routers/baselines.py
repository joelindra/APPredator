from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.baseline_store import (
    DEFAULT_BASELINE_PATH,
    add_baseline_entry,
    delete_baseline_entry,
    load_baselines,
)
router = APIRouter(prefix="/api/baselines", tags=["baselines"])


class BaselineAddBody(BaseModel):
    fingerprint: str
    application_id: str
    reason: str
    created_by: Optional[str] = None


@router.get("")
def list_baselines() -> dict[str, Any]:
    return {"entries": load_baselines(), "path": str(DEFAULT_BASELINE_PATH)}


@router.post("")
def add_baseline(body: BaselineAddBody) -> dict[str, Any]:
    entry = add_baseline_entry(
        body.fingerprint,
        body.application_id,
        body.reason,
        created_by=body.created_by,
    )
    return {"entry": entry}


@router.delete("/{entry_id}")
def remove_baseline(entry_id: str) -> dict[str, Any]:
    if not delete_baseline_entry(entry_id):
        raise HTTPException(404, "Entry not found")
    return {"deleted": entry_id}
