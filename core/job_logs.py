"""
Per-scan job log capture for WebSocket streaming.

Register a job sink before starting a scan; unregister when finished.
Messages are plain text lines; optional redaction for API keys in verbose logs.
"""
from __future__ import annotations

import re
import threading
from collections import deque
from pathlib import Path
from typing import Callable, Deque, Dict, Optional

_MAX_LINES_PER_JOB = 5000
_SENSITIVE_PATTERNS = (
    re.compile(r"(api[_-]?key|token|secret|password)\s*[:=]\s*\S+", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.I),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}", re.I),
)

_job_buffers: Dict[str, Deque[str]] = {}
_job_disk_paths: Dict[str, Path] = {}
_job_lock = threading.Lock()


def _redact_line(text: str) -> str:
    out = text
    for pat in _SENSITIVE_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def register_job_sink(job_id: str, *, persist_path: Optional[Path] = None) -> None:
    with _job_lock:
        _job_buffers[job_id] = deque(maxlen=_MAX_LINES_PER_JOB)
        if persist_path is not None:
            _job_disk_paths[job_id] = persist_path
    if persist_path is not None:
        try:
            persist_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


def unregister_job_sink(job_id: str) -> None:
    with _job_lock:
        _job_buffers.pop(job_id, None)
        _job_disk_paths.pop(job_id, None)


def append_job_log(job_id: str, line: str, *, redact: bool = True) -> None:
    text = _redact_line(line) if redact else line
    text = text.rstrip("\n")
    disk: Optional[Path] = None
    with _job_lock:
        buf = _job_buffers.get(job_id)
        if buf is not None:
            buf.append(text)
        disk = _job_disk_paths.get(job_id)
    if disk is not None:
        try:
            with open(disk, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass


def get_job_log_tail(job_id: str, last_n: int = 200) -> list[str]:
    with _job_lock:
        buf = _job_buffers.get(job_id)
        if not buf:
            return []
        items = list(buf)
    return items[-last_n:]


def _persisted_log_path(job_id: str) -> Path:
    return Path("output") / "uploads" / job_id / "scan.log"


def get_job_log_copy(job_id: str) -> list[str]:
    """In-memory lines while the job runs; after completion reads ``scan.log`` under uploads."""
    with _job_lock:
        buf = _job_buffers.get(job_id)
        if buf:
            return list(buf)
    p = _persisted_log_path(job_id)
    if p.is_file():
        try:
            return p.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
    return []


def make_loguru_sink(job_id: str, *, redact: bool = True) -> Callable:
    def sink(message):
        append_job_log(job_id, message.record["message"], redact=redact)

    return sink
