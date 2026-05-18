from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Optional

from core import log
from core.job_logs import register_job_sink, unregister_job_sink
from core.logger import attach_job_log_sink, detach_log_sink, setup_logger
from core.scan_runner import ScanFlags, run_scan

from web.backend import jobs_store

_scan_semaphore: Optional[asyncio.Semaphore] = None


def get_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore
    if _scan_semaphore is None:
        n = max(1, int(os.environ.get("APPREDATOR_MAX_CONCURRENT_SCANS", "2")))
        _scan_semaphore = asyncio.Semaphore(n)
    return _scan_semaphore


def _run_scan_sync(
    job_id: str,
    apk_path: str,
    flags: ScanFlags,
    settings_overrides: Optional[dict[str, Any]],
    verbose: bool,
) -> None:
    log_path = Path(apk_path).parent / "scan.log"
    register_job_sink(job_id, persist_path=log_path)
    hid = None
    try:
        setup_logger(verbose)
        hid = attach_job_log_sink(job_id, redact=True)

        jobs_store.update_job(job_id, status="running")
        def _partial_sink(chunk: list[dict[str, Any]]) -> None:
            jobs_store.append_partial_findings(job_id, chunk)

        result = run_scan(
            apk_path,
            flags,
            settings_overrides=settings_overrides,
            on_partial_results=_partial_sink,
        )
        if result.success:
            prev = (jobs_store.get_job(job_id) or {}).get("meta") or {}
            if not isinstance(prev, dict):
                prev = {}
            jobs_store.update_job(
                job_id,
                status="completed",
                report_json_path=result.output_json_path,
                meta={**prev, "findings_summary": result.findings_summary},
            )
        else:
            jobs_store.update_job(job_id, status="failed", error=result.error or "Unknown error")
    except Exception as e:
        jobs_store.update_job(job_id, status="failed", error=str(e))
        log.error(f"Job {job_id} failed: {e}")
    finally:
        if hid is not None:
            detach_log_sink(hid)
        unregister_job_sink(job_id)


async def run_scan_job_async(
    job_id: str,
    apk_path: str,
    flags: ScanFlags,
    settings_overrides: Optional[dict[str, Any]],
    verbose: bool,
) -> None:
    sem = get_semaphore()
    async with sem:
        await asyncio.to_thread(_run_scan_sync, job_id, apk_path, flags, settings_overrides, verbose)
