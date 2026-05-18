from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from core.baseline_store import fingerprints_for_report
from core.scan_history import diff_with_previous
from core.job_logs import get_job_log_copy
from core.reporting.html_report import report_to_html_string
from core.reporting.sarif import load_report_from_path, report_to_sarif
from core.scan_runner import ScanFlags
from web.backend import jobs_store
from web.backend.scan_worker import run_scan_job_async
router = APIRouter(prefix="/api/scans", tags=["scans"])


def _max_upload_bytes() -> int:
    mb = int(os.environ.get("APPREDATOR_MAX_UPLOAD_MB", "512"))
    return mb * 1024 * 1024


@router.get("")
def list_scans(limit: int = 50) -> dict[str, Any]:
    return {"jobs": jobs_store.list_jobs(limit)}


@router.post("")
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    options: str = Form(default="{}"),
) -> dict[str, Any]:
    try:
        opts = json.loads(options)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid options JSON: {e}") from e

    raw = await file.read()
    if len(raw) > _max_upload_bytes():
        raise HTTPException(413, "Upload too large")

    job_id = jobs_store.create_job(meta={"filename": file.filename})
    upload_dir = Path("output") / "uploads" / job_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(file.filename or "app.apk").suffix.lower()
    if ext not in (".apk", ".xapk"):
        ext = ".apk"
    apk_path = upload_dir / f"input{ext}"
    apk_path.write_bytes(raw)

    flags = ScanFlags(
        output=opts.get("output"),
        no_decompile=bool(opts.get("no_decompile", False)),
        rules=opts.get("rules"),
        profile=opts.get("profile"),
        generate_exploit=bool(opts.get("generate_exploit", False)),
        scan_libraries=bool(opts.get("scan_libraries", False)),
    )
    overrides = opts.get("settings_overrides")
    verbose = bool(opts.get("verbose", False))

    jobs_store.update_job(job_id, status="queued", apk_path=str(apk_path))

    async def _job():
        await run_scan_job_async(job_id, str(apk_path), flags, overrides, verbose)

    background_tasks.add_task(_job)

    return {"job_id": job_id, "status": "queued"}


@router.get("/{job_id}")
def get_scan(job_id: str) -> dict[str, Any]:
    job = jobs_store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/{job_id}/findings-live")
def get_scan_findings_live(job_id: str) -> dict[str, Any]:
    job = jobs_store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    meta = job.get("meta") or {}
    findings = meta.get("partial_findings") if isinstance(meta.get("partial_findings"), list) else []
    severity = meta.get("severity_counts") if isinstance(meta.get("severity_counts"), dict) else {}
    categories = meta.get("category_counts") if isinstance(meta.get("category_counts"), dict) else {}
    triage_counts = meta.get("triage_counts") if isinstance(meta.get("triage_counts"), dict) else {}
    timeline = meta.get("timeline_points") if isinstance(meta.get("timeline_points"), list) else []
    # Keep response UI-friendly and bounded.
    findings_out = findings[-1000:]
    timeline_out = timeline[-250:]
    cat_sorted = sorted(((str(k), int(v)) for k, v in categories.items()), key=lambda kv: kv[1], reverse=True)
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "last_partial_at": meta.get("last_partial_at"),
        "summary": {
            "total_count": len(findings),
            "vulnerable_count": sum(1 for x in findings if isinstance(x, dict) and x.get("status") == "Vulnerable"),
            "severity_counts": severity,
            "category_counts": {k: v for k, v in cat_sorted[:30]},
            "triage_counts": triage_counts,
        },
        "findings": findings_out,
        "timeline_points": timeline_out,
    }


@router.get("/{job_id}/logs")
def get_scan_logs(job_id: str) -> dict[str, Any]:
    if not jobs_store.get_job(job_id):
        raise HTTPException(404, "Job not found")
    lines = get_job_log_copy(job_id)
    return {"lines": lines, "line_count": len(lines)}


@router.websocket("/{job_id}/logs")
async def scan_logs_ws(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    try:
        import asyncio

        lines = get_job_log_copy(job_id)
        for line in lines:
            await websocket.send_text(line)
        sent = len(lines)

        while True:
            job = jobs_store.get_job(job_id)
            if not job:
                break
            st = job.get("status")
            lines = get_job_log_copy(job_id)
            if len(lines) > sent:
                for line in lines[sent:]:
                    await websocket.send_text(line)
                sent = len(lines)
            if st in ("completed", "failed"):
                await websocket.send_text(f"[job {st}]")
                break
            await asyncio.sleep(0.35)
    except WebSocketDisconnect:
        return


@router.get("/{job_id}/artifacts")
def get_artifacts(
    job_id: str,
    format: str = "json",
) -> Any:
    job = jobs_store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    path = job.get("report_json_path")
    if not path or not os.path.isfile(path):
        raise HTTPException(404, "Report not ready")

    fmt = (format or "json").lower()
    if fmt == "json":
        return FileResponse(path, media_type="application/json", filename=f"{job_id}_report.json")

    data = load_report_from_path(path)
    baseline_fps = fingerprints_for_report(data)

    if fmt == "sarif":
        sarif = report_to_sarif(data, baseline_ids=baseline_fps)
        return JSONResponse(content=sarif)

    if fmt == "html":
        html = report_to_html_string(data, baseline_fps=baseline_fps)
        return HTMLResponse(content=html)

    raise HTTPException(400, "format must be json, sarif, or html")


@router.get("/{job_id}/diff")
def get_scan_diff(job_id: str) -> dict[str, Any]:
    job = jobs_store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    path = job.get("report_json_path")
    if not path or not os.path.isfile(path):
        raise HTTPException(404, "Report not ready")
    data = load_report_from_path(path)
    summary = data.get("diff_summary")
    if isinstance(summary, dict):
        return summary
    apk_version = Path(str(job.get("apk_path") or "")).name or job_id
    app_id = "unknown"
    app_summary = data.get("app_summary")
    if isinstance(app_summary, str) and "package" in app_summary.lower():
        app_id = "unknown"
    return diff_with_previous(
        apk_version=apk_version,
        application_id=app_id,
        results=data.get("results") or [],
    )


@router.delete("/{job_id}")
def delete_scan(job_id: str, delete_artifacts: bool = False) -> dict[str, Any]:
    if not jobs_store.get_job(job_id):
        raise HTTPException(404, "Job not found")
    jobs_store.delete_job(job_id, delete_upload=True)
    return {"deleted": job_id}
