"""
Baseline / suppressions: JSON file with fingerprint per application_id.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_BASELINE_PATH = Path(os.environ.get("APPREDATOR_BASELINE_PATH", "config/baselines/default.json"))


def _snippet_hash(text: Optional[str], max_len: int = 400) -> str:
    if not text:
        return "none"
    chunk = text[:max_len] if isinstance(text, str) else str(text)[:max_len]
    return hashlib.sha256(chunk.encode("utf-8", errors="ignore")).hexdigest()[:16]


def normalize_path(p: str) -> str:
    return p.replace("\\", "/").strip()


def fingerprint_finding(
    rule_id: str,
    file_path: str,
    result: dict[str, Any],
    *,
    application_id: str = "unknown",
) -> str:
    """Stable fingerprint for baseline matching."""
    snippet = (
        (result or {}).get("evidence")
        or (result or {}).get("description")
        or ""
    )
    raw = "|".join(
        [
            application_id,
            rule_id.lower().strip(),
            normalize_path(file_path or ""),
            _snippet_hash(str(snippet)),
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def extract_application_id(report: dict[str, Any]) -> str:
    """Best-effort package id from report JSON."""
    summary = report.get("app_summary")
    if isinstance(summary, str):
        m = re.search(r"package(?:\s+name)?[:\s]+([a-zA-Z0-9_.]+)", summary, re.I)
        if m:
            return m.group(1)
    asm = report.get("attack_surface_map")
    if isinstance(asm, str):
        m = re.search(r"([a-z][a-z0-9_]*\.[a-z][a-z0-9_.]+)", asm, re.I)
        if m:
            return m.group(1)[:200]
    return "unknown"


def load_baselines(path: Optional[Path] = None) -> list[dict[str, Any]]:
    p = path or DEFAULT_BASELINE_PATH
    if not p.is_file():
        return []
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("entries", [])


def save_baselines(entries: list[dict[str, Any]], path: Optional[Path] = None) -> None:
    p = path or DEFAULT_BASELINE_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"entries": entries}, f, indent=2)


def add_baseline_entry(
    fingerprint: str,
    application_id: str,
    reason: str,
    *,
    created_by: Optional[str] = None,
    path: Optional[Path] = None,
) -> dict[str, Any]:
    entries = load_baselines(path)
    entry = {
        "id": str(uuid.uuid4()),
        "fingerprint": fingerprint,
        "application_id": application_id,
        "reason": reason,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    entries.append(entry)
    save_baselines(entries, path)
    return entry


def delete_baseline_entry(entry_id: str, path: Optional[Path] = None) -> bool:
    entries = load_baselines(path)
    new_entries = [e for e in entries if e.get("id") != entry_id]
    if len(new_entries) == len(entries):
        return False
    save_baselines(new_entries, path)
    return True


def fingerprints_for_report(report: dict[str, Any], path: Optional[Path] = None) -> set[str]:
    """All fingerprints from current report that exist in baseline store for this app."""
    app_id = extract_application_id(report)
    entries = load_baselines(path)
    allowed = {e["fingerprint"] for e in entries if e.get("application_id") in (app_id, "global", "unknown")}
    out: set[str] = set()
    for item in report.get("results") or []:
        if item.get("status") != "Vulnerable":
            continue
        res = item.get("result") or {}
        rule = (item.get("vulnerability") or "rule").lower().replace(" ", "_")
        fp = fingerprint_finding(rule, item.get("file") or "", res, application_id=app_id)
        if fp in allowed:
            out.add(fp)
    return out


def match_fingerprint_in_store(fp: str, path: Optional[Path] = None) -> bool:
    return any(e.get("fingerprint") == fp for e in load_baselines(path))
