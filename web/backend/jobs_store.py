"""
SQLite job index for the web UI.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from core.finding_utils import canonical_finding_key, enrich_result_common, normalize_severity

def _db_path() -> Path:
    return Path(os.environ.get("APPREDATOR_JOB_DB_PATH", "web_data/jobs.sqlite"))


def init_db() -> None:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(p) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                apk_path TEXT,
                report_json_path TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                meta_json TEXT
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    init_db()
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def create_job(meta: Optional[dict[str, Any]] = None) -> str:
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    import json

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, status, created_at, updated_at, meta_json) VALUES (?, ?, ?, ?, ?)",
            (job_id, "pending", now, now, json.dumps(meta or {})),
        )
        conn.commit()
    return job_id


def update_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    apk_path: Optional[str] = None,
    report_json_path: Optional[str] = None,
    error: Optional[str] = None,
    meta: Optional[dict[str, Any]] = None,
) -> None:
    import json

    now = datetime.now(timezone.utc).isoformat()
    fields: list[str] = ["updated_at = ?"]
    vals: list[Any] = [now]
    if status is not None:
        fields.append("status = ?")
        vals.append(status)
    if apk_path is not None:
        fields.append("apk_path = ?")
        vals.append(apk_path)
    if report_json_path is not None:
        fields.append("report_json_path = ?")
        vals.append(report_json_path)
    if error is not None:
        fields.append("error = ?")
        vals.append(error)
    if meta is not None:
        fields.append("meta_json = ?")
        vals.append(json.dumps(meta))

    vals.append(job_id)
    with get_conn() as conn:
        conn.execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", vals)
        conn.commit()


def _ensure_live_meta(meta: dict[str, Any]) -> dict[str, Any]:
    m = dict(meta or {})
    if not isinstance(m.get("partial_findings"), list):
        m["partial_findings"] = []
    if not isinstance(m.get("severity_counts"), dict):
        m["severity_counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    if not isinstance(m.get("category_counts"), dict):
        m["category_counts"] = {}
    if not isinstance(m.get("timeline_points"), list):
        m["timeline_points"] = []
    if not isinstance(m.get("triage_counts"), dict):
        m["triage_counts"] = {"critical_now": 0, "review": 0, "info": 0}
    if not isinstance(m.get("_finding_ids"), list):
        m["_finding_ids"] = []
    return m


def _safe_text(v: Any, limit: int = 1200) -> str:
    s = str(v or "").strip()
    return s[:limit]


def _normalize_finding(item: dict[str, Any], *, ts: str) -> dict[str, Any]:
    res = item.get("result") or {}
    if not isinstance(res, dict):
        res = {}
    vuln = _safe_text(item.get("vulnerability"), 128) or "Unknown"
    file_path = _safe_text(item.get("file"), 1024)
    enriched = enrich_result_common(file_path=file_path, vulnerability=vuln, result=res)
    sev = normalize_severity(enriched.get("severity"))
    conf = _safe_text(enriched.get("confidence"), 32)
    evidence = _safe_text(res.get("evidence"))
    desc = _safe_text(res.get("description"))
    status = _safe_text(item.get("status"), 32) or "Unknown"
    finding_id = canonical_finding_key(
        file_path=file_path,
        vulnerability=vuln,
        status=status,
        evidence=evidence or desc,
    )
    return {
        "id": finding_id,
        "ts": ts,
        "file": file_path,
        "vulnerability": vuln,
        "status": status,
        "severity": sev,
        "confidence": conf,
        "evidence": evidence,
        "description": desc,
        "triage_level": _safe_text(enriched.get("triage_level"), 32),
        "triage_reason": _safe_text(enriched.get("triage_reason"), 200),
        "owasp_mobile_top10": _safe_text(enriched.get("owasp_mobile_top10"), 64),
        "remediation_summary": _safe_text(enriched.get("remediation_summary"), 260),
    }


def append_partial_findings(job_id: str, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    from datetime import datetime, timezone

    job = get_job(job_id)
    if not job:
        return
    ts = datetime.now(timezone.utc).isoformat()
    meta = _ensure_live_meta(job.get("meta") or {})
    seen = set(str(x) for x in meta.get("_finding_ids") or [])
    partial = list(meta.get("partial_findings") or [])
    sev_counts = dict(meta.get("severity_counts") or {})
    cat_counts = dict(meta.get("category_counts") or {})
    triage_counts = dict(meta.get("triage_counts") or {})

    changed = False
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        n = _normalize_finding(raw, ts=ts)
        fid = n["id"]
        if fid in seen:
            continue
        seen.add(fid)
        partial.append(n)
        changed = True
        sev = n.get("severity") or "unknown"
        sev_counts[sev] = int(sev_counts.get(sev, 0)) + 1
        cat = n.get("vulnerability") or "Unknown"
        cat_counts[cat] = int(cat_counts.get(cat, 0)) + 1
        t = n.get("triage_level") or "info"
        triage_counts[t] = int(triage_counts.get(t, 0)) + 1

    if not changed:
        return

    vulnerable_count = sum(1 for x in partial if str(x.get("status")) == "Vulnerable")
    timeline = list(meta.get("timeline_points") or [])
    timeline.append(
        {
            "ts": ts,
            "total_count": len(partial),
            "vulnerable_count": vulnerable_count,
        }
    )
    # Keep bounded history to avoid unbounded row growth.
    if len(timeline) > 500:
        timeline = timeline[-500:]
    if len(partial) > 4000:
        partial = partial[-4000:]
        seen = set(str(x.get("id")) for x in partial if isinstance(x, dict) and x.get("id"))
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        cat_counts = {}
        triage_counts = {"critical_now": 0, "review": 0, "info": 0}
        for it in partial:
            sev = str(it.get("severity") or "unknown").lower()
            sev_counts[sev] = int(sev_counts.get(sev, 0)) + 1
            cat = str(it.get("vulnerability") or "Unknown")
            cat_counts[cat] = int(cat_counts.get(cat, 0)) + 1
            t = str(it.get("triage_level") or "info")
            triage_counts[t] = int(triage_counts.get(t, 0)) + 1

    meta["partial_findings"] = partial
    meta["severity_counts"] = sev_counts
    meta["category_counts"] = cat_counts
    meta["triage_counts"] = triage_counts
    meta["timeline_points"] = timeline
    meta["last_partial_at"] = ts
    meta["_finding_ids"] = sorted(seen)
    update_job(job_id, meta=meta)


def get_job(job_id: str) -> Optional[dict[str, Any]]:
    import json

    with get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["meta"] = json.loads(d.pop("meta_json") or "{}")
    except json.JSONDecodeError:
        d["meta"] = {}
    return d


def list_jobs(limit: int = 50) -> list[dict[str, Any]]:
    import json

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY datetime(updated_at) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try:
            d["meta"] = json.loads(d.pop("meta_json") or "{}")
        except json.JSONDecodeError:
            d["meta"] = {}
        out.append(d)
    return out


def delete_job(job_id: str, delete_upload: bool = True) -> bool:
    job = get_job(job_id)
    if not job:
        return False
    if delete_upload and job.get("apk_path"):
        try:
            p = Path(job["apk_path"])
            if p.is_file():
                p.unlink()
            parent = p.parent
            if parent.is_dir() and parent.name != "output" and "uploads" in str(parent):
                try:
                    parent.rmdir()
                except OSError:
                    pass
        except OSError:
            pass
    with get_conn() as conn:
        conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
    return True
