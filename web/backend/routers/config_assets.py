"""
Read/write prompt templates and knowledge-base JSON under config/ (bounded paths only).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/config/assets", tags=["config"])

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CONFIG = _PROJECT_ROOT / "config"
_ALLOWED_PREFIXES = (
    (_CONFIG / "prompts").resolve(),
    (_CONFIG / "knowledge_base").resolve(),
)
_MAX_BYTES = 2 * 1024 * 1024
_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_BASENAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,120}$")


def _parse_subpath(subpath: str) -> list[str]:
    s = (subpath or "").strip().replace("\\", "/").strip("/")
    if not s:
        return []
    parts = [p for p in s.split("/") if p]
    for p in parts:
        if not _SEGMENT_RE.match(p):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid subpath segment {p!r}: use letters, digits, underscore, hyphen; max 64 chars per segment.",
            )
    return parts


def _normalize_txt_basename(name: str) -> str:
    n = (name or "").strip()
    if n.lower().endswith(".txt"):
        n = n[:-4].strip()
    if not n:
        raise HTTPException(status_code=400, detail="File name is required")
    if not _BASENAME_RE.match(n):
        raise HTTPException(
            status_code=400,
            detail="File name must be 1–120 characters: letters, digits, underscore, and hyphen only (saved as .txt).",
        )
    return n


def _resolve_asset(rel: str) -> Path:
    rel = rel.replace("\\", "/").strip().lstrip("/")
    if not rel or ".." in rel.split("/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    full = (_CONFIG / rel).resolve()
    for prefix in _ALLOWED_PREFIXES:
        try:
            full.relative_to(prefix)
            return full
        except ValueError:
            continue
    raise HTTPException(status_code=400, detail="Path must be under config/prompts or config/knowledge_base")


def _list_files_recursive(root: Path, prefix: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        try:
            rel = p.relative_to(_CONFIG).as_posix()
        except ValueError:
            continue
        ext = p.suffix.lower()
        kind = "json" if ext == ".json" else "text"
        out.append({"path": rel, "kind": kind, "group": prefix})
    return out


@router.get("/files")
def list_asset_files() -> dict[str, Any]:
    prompts = _list_files_recursive(_CONFIG / "prompts", "prompts")
    kb = _list_files_recursive(_CONFIG / "knowledge_base", "knowledge_base")
    return {"files": prompts + kb}


@router.get("/content")
def get_asset_content(path: str = Query(..., description="Relative to config/, e.g. prompts/system_prompt.txt")) -> dict[str, Any]:
    full = _resolve_asset(path)
    if not full.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    size = full.stat().st_size
    if size > _MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large for editor")
    text = full.read_text(encoding="utf-8")
    return {"path": path.replace("\\", "/").lstrip("/"), "content": text, "size": size}


class AssetContentBody(BaseModel):
    path: str = Field(..., description="Relative to config/")
    content: str = Field(..., description="Full file body to write")


class CreateTxtBody(BaseModel):
    folder: Literal["prompts", "knowledge_base"] = Field(..., description="Target tree under config/")
    basename: str = Field(..., description="File name without path; .txt added if omitted")
    subpath: str = Field("", description="Optional nested folders under that tree, slash-separated")


@router.post("/create-txt", status_code=status.HTTP_201_CREATED)
def create_txt_asset(body: CreateTxtBody) -> dict[str, Any]:
    """Create a new empty UTF-8 text file; extension is always .txt."""
    base = _normalize_txt_basename(body.basename)
    sub_parts = _parse_subpath(body.subpath)
    rel = "/".join([body.folder, *sub_parts, f"{base}.txt"])
    full = _resolve_asset(rel)
    if full.exists():
        raise HTTPException(status_code=409, detail="A file at that path already exists")
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text("", encoding="utf-8", newline="\n")
    return {"ok": True, "path": rel}


@router.put("/content")
def put_asset_content(body: AssetContentBody) -> dict[str, Any]:
    full = _resolve_asset(body.path)
    raw = body.content.encode("utf-8")
    if len(raw) > _MAX_BYTES:
        raise HTTPException(status_code=413, detail="Content too large")
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(body.content, encoding="utf-8", newline="\n")
    return {"ok": True, "path": body.path.replace("\\", "/").lstrip("/"), "bytes": len(raw)}
