from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.baseline_store import fingerprint_finding


DEFAULT_SCAN_HISTORY_PATH = Path(os.environ.get("APPREDATOR_SCAN_HISTORY_PATH", "config/baselines/scan_history.json"))


def _load_raw(path: Path = DEFAULT_SCAN_HISTORY_PATH) -> dict[str, Any]:
    if not path.is_file():
        return {"entries": []}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {"entries": []}
    if not isinstance(data.get("entries"), list):
        data["entries"] = []
    return data


def _save_raw(data: dict[str, Any], path: Path = DEFAULT_SCAN_HISTORY_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _fingerprints_for_results(results: list[dict[str, Any]], application_id: str) -> set[str]:
    out: set[str] = set()
    for item in results:
        if item.get("status") != "Vulnerable":
            continue
        rule = str(item.get("vulnerability") or "rule").lower().replace(" ", "_")
        fp = fingerprint_finding(
            rule,
            str(item.get("file") or ""),
            item.get("result") or {},
            application_id=application_id,
        )
        out.add(fp)
    return out


def record_scan(
    *,
    apk_version: str,
    application_id: str,
    report_path: str,
    results: list[dict[str, Any]],
    path: Path = DEFAULT_SCAN_HISTORY_PATH,
) -> dict[str, Any]:
    data = _load_raw(path)
    fp_list = sorted(_fingerprints_for_results(results, application_id))
    entry = {
        "apk_version": apk_version,
        "application_id": application_id or "unknown",
        "report_path": report_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fingerprints": fp_list,
    }
    data["entries"].append(entry)
    if len(data["entries"]) > 300:
        data["entries"] = data["entries"][-300:]
    _save_raw(data, path)
    return entry


def previous_entry(*, apk_version: str, application_id: str, path: Path = DEFAULT_SCAN_HISTORY_PATH) -> dict[str, Any] | None:
    entries = _load_raw(path).get("entries") or []
    candidates = [
        x for x in entries
        if str(x.get("application_id") or "") == (application_id or "unknown")
        and str(x.get("apk_version") or "") != apk_version
    ]
    if not candidates:
        return None
    return candidates[-1]


def diff_with_previous(*, apk_version: str, application_id: str, results: list[dict[str, Any]], path: Path = DEFAULT_SCAN_HISTORY_PATH) -> dict[str, Any]:
    current = _fingerprints_for_results(results, application_id)
    prev = previous_entry(apk_version=apk_version, application_id=application_id, path=path)
    prev_set = set(prev.get("fingerprints") or []) if prev else set()
    new_set = current - prev_set
    resolved_set = prev_set - current
    unchanged_set = current & prev_set
    return {
        "apk_version": apk_version,
        "application_id": application_id,
        "previous_apk_version": (prev or {}).get("apk_version"),
        "new_count": len(new_set),
        "resolved_count": len(resolved_set),
        "unchanged_count": len(unchanged_set),
        "new_fingerprints": sorted(new_set),
        "resolved_fingerprints": sorted(resolved_set),
    }
