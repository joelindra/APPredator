from __future__ import annotations

import json
import math
import os
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from core.config_loader import load_settings
from core.ssl_pinning_mapper import analyze_decompiled_tree
from modules.decompiler.apktool_handler import ApktoolHandler
from modules.decompiler.jadx_handler import JadxHandler, normalize_jadx_max_heap_arg, resolved_jadx_max_heap

router = APIRouter(prefix="/api/ssl-pinning", tags=["ssl-pinning"])

# Apktool/JADX/scan workers use daemon threads so SIGINT (Ctrl+C) and interpreter shutdown do not block
# indefinitely in threading._shutdown() while a child subprocess is still running (common on Windows).


def _max_upload_bytes() -> int:
    mb = int(os.environ.get("APPREDATOR_MAX_UPLOAD_MB", "512"))
    return mb * 1024 * 1024


def _progress(pct: int, stage: str, message: str) -> dict:
    return {"type": "progress", "pct": max(0, min(100, pct)), "stage": stage, "message": message}


def _jadx_heartbeat_progress(
    elapsed_sec: float,
    *,
    last_pct: int,
    pct_floor: int,
    pct_cap: int,
    heap_disp: str,
    tick: int,
) -> tuple[int, str]:
    """
    Map elapsed time to a monotonic percentage between pct_floor and pct_cap (exclusive of final milestones).
    Uses a saturating exponential so early seconds move faster, then eases toward pct_cap.
    """
    span = max(1, pct_cap - pct_floor)
    eased = 1.0 - math.exp(-elapsed_sec / 95.0)
    target = pct_floor + int(span * eased)
    target = min(max(target, last_pct + 1), pct_cap)
    if tick % 3 == 0:
        msg = f"JADX: decompiling DEX -> Java sources - {int(elapsed_sec)}s - -Xmx {heap_disp}"
    elif tick % 3 == 1:
        msg = f"JADX: JVM working (CPU + disk) - {int(elapsed_sec)}s elapsed; large apps can take several minutes"
    else:
        msg = f"JADX: still running... {int(elapsed_sec)}s - progress advances while this step completes"
    return target, msg


def _apktool_heartbeat_progress(
    elapsed_sec: float,
    *,
    last_pct: int,
    pct_floor: int,
    pct_cap: int,
    tick: int,
) -> tuple[int, str]:
    """Same easing idea as JADX; slightly shorter time constant (Apktool often finishes sooner)."""
    span = max(1, pct_cap - pct_floor)
    eased = 1.0 - math.exp(-elapsed_sec / 72.0)
    target = pct_floor + int(span * eased)
    target = min(max(target, last_pct + 1), pct_cap)
    if tick % 3 == 0:
        msg = f"Apktool: decoding resources and AndroidManifest - {int(elapsed_sec)}s"
    elif tick % 3 == 1:
        msg = f"Apktool: extracting Smali and assets - {int(elapsed_sec)}s (I/O heavy on large APKs)"
    else:
        msg = f"Apktool: still running... {int(elapsed_sec)}s - percentage climbs until this step finishes"
    return target, msg


def _scan_heartbeat_progress(
    elapsed_sec: float,
    *,
    last_pct: int,
    pct_floor: int,
    pct_cap: int,
    tick: int,
) -> tuple[int, str]:
    """Pinning mapper static scan can be slow on huge trees; ease 88 -> pct_cap."""
    span = max(1, pct_cap - pct_floor)
    eased = 1.0 - math.exp(-elapsed_sec / 80.0)
    target = pct_floor + int(span * eased)
    target = min(max(target, last_pct + 1), pct_cap)
    if tick % 3 == 0:
        msg = f"Scan: walking Smali/Java for pinning hooks - {int(elapsed_sec)}s"
    elif tick % 3 == 1:
        msg = f"Scan: matching libraries (OkHttp, TrustKit, NSC, ...) - {int(elapsed_sec)}s"
    else:
        msg = f"Scan: still running... {int(elapsed_sec)}s - percentage climbs until this step finishes"
    return target, msg


def _ssl_pinning_events(raw: bytes, filename: str | None, jadx_max_heap: str | None = None) -> Iterator[dict]:
    """
    Yields progress events, then either a complete event with the result payload or an error event.
    """
    if len(raw) > _max_upload_bytes():
        yield {"type": "error", "message": "Upload too large"}
        return

    ext = Path(filename or "app.apk").suffix.lower()
    if ext not in (".apk", ".xapk"):
        ext = ".apk"

    tmp_root = Path(tempfile.gettempdir()) / f"apppredator_ssl_{uuid.uuid4().hex}"
    tmp_root.mkdir(parents=True, exist_ok=True)
    apk_path = tmp_root / f"input{ext}"
    out_dir = tmp_root / "decompiled"

    try:
        yield _progress(4, "save", "Saving package to a temporary workspace…")
        apk_path.write_bytes(raw)
        settings = load_settings()
        out_dir.mkdir(parents=True, exist_ok=True)

        yield _progress(
            12,
            "apktool",
            "Apktool started - Smali, manifest, resources. Percentage will climb toward ~41% while this step runs.",
        )
        apk_s = str(apk_path)
        out_s = str(out_dir)
        decompiler = ApktoolHandler(apktool_path=settings.apktool.path or "apktool")
        ap_holder: dict[str, Any] = {"exc": None, "done": False}

        def _apktool_worker() -> None:
            try:
                decompiler.decompile(apk_s, out_s)
            except Exception as e:  # noqa: BLE001 — propagate after join
                ap_holder["exc"] = e
            finally:
                ap_holder["done"] = True

        ap_th = threading.Thread(target=_apktool_worker, name="apppredator-apktool", daemon=True)
        ap_t0 = time.monotonic()
        ap_th.start()
        ap_last = 12
        ap_cap = 41
        ap_tick = 0
        while not ap_holder["done"]:
            ap_th.join(timeout=2.25)
            if ap_holder["done"]:
                break
            ap_tick += 1
            ap_elapsed = time.monotonic() - ap_t0
            ap_last, ap_msg = _apktool_heartbeat_progress(
                ap_elapsed,
                last_pct=ap_last,
                pct_floor=12,
                pct_cap=ap_cap,
                tick=ap_tick,
            )
            yield _progress(ap_last, "apktool", ap_msg)

        ap_th.join()
        if ap_holder["exc"] is not None:
            raise ap_holder["exc"]
        yield _progress(42, "apktool", "Apktool finished.")

        jx = settings.jadx
        jadx = JadxHandler(jadx_path=jx.path if jx else None, max_heap=jx.max_heap if jx else None)
        if jadx.is_available():
            heap_disp = resolved_jadx_max_heap(
                max_heap_override=jadx_max_heap,
                max_heap_from_settings=jx.max_heap if jx else None,
            )
            java_opts = bool(os.environ.get("APPREDATOR_JADX_JAVA_OPTS", "").strip())
            if java_opts:
                yield _progress(
                    48,
                    "jadx",
                    "JADX started - server APPREDATOR_JADX_JAVA_OPTS overrides heap; sub-progress will advance while decompile runs.",
                )
            else:
                yield _progress(
                    48,
                    "jadx",
                    f"JADX started (Java decompile, -Xmx {heap_disp}). Percentage will climb toward ~77% while this step runs; "
                    "it can take several minutes on large / many-DEX APKs.",
                )

            holder: dict[str, Any] = {"ok": None, "exc": None, "done": False}
            apk_s = str(apk_path)
            out_s = str(out_dir)

            def _jadx_worker() -> None:
                try:
                    holder["ok"] = jadx.decompile(apk_s, out_s, max_heap_override=jadx_max_heap)
                except Exception as e:  # noqa: BLE001 — propagate after join
                    holder["exc"] = e
                finally:
                    holder["done"] = True

            th = threading.Thread(target=_jadx_worker, name="apppredator-jadx", daemon=True)
            t0 = time.monotonic()
            th.start()
            last_pct = 48
            jadx_cap = 77
            tick = 0
            while not holder["done"]:
                th.join(timeout=2.25)
                if holder["done"]:
                    break
                tick += 1
                elapsed = time.monotonic() - t0
                last_pct, hb_msg = _jadx_heartbeat_progress(
                    elapsed,
                    last_pct=last_pct,
                    pct_floor=48,
                    pct_cap=jadx_cap,
                    heap_disp=heap_disp,
                    tick=tick,
                )
                yield _progress(last_pct, "jadx", hb_msg)

            th.join()
            if holder["exc"] is not None:
                raise holder["exc"]
            jadx_ok = bool(holder["ok"])
            if jadx_ok:
                yield _progress(78, "jadx", "JADX finished (Java sources available).")
            else:
                yield _progress(
                    72,
                    "jadx",
                    "JADX failed or produced no sources/ - continuing scan from Smali only.",
                )
        else:
            yield _progress(55, "jadx", "JADX not configured; skipping Java decompile.")

        yield _progress(
            88,
            "scan",
            "Scan started - static SSL pinning patterns across decompiled tree. Percentage climbs toward ~97% while this step runs.",
        )
        scan_holder: dict[str, Any] = {"result": None, "exc": None, "done": False}
        out_scan = str(out_dir)

        def _scan_worker() -> None:
            try:
                scan_holder["result"] = analyze_decompiled_tree(out_scan)
            except Exception as e:  # noqa: BLE001
                scan_holder["exc"] = e
            finally:
                scan_holder["done"] = True

        sc_th = threading.Thread(target=_scan_worker, name="apppredator-ssl-pin-scan", daemon=True)
        sc_t0 = time.monotonic()
        sc_th.start()
        sc_last = 88
        sc_cap = 97
        sc_tick = 0
        while not scan_holder["done"]:
            sc_th.join(timeout=2.25)
            if scan_holder["done"]:
                break
            sc_tick += 1
            sc_elapsed = time.monotonic() - sc_t0
            sc_last, sc_msg = _scan_heartbeat_progress(
                sc_elapsed,
                last_pct=sc_last,
                pct_floor=88,
                pct_cap=sc_cap,
                tick=sc_tick,
            )
            yield _progress(sc_last, "scan", sc_msg)

        sc_th.join()
        if scan_holder["exc"] is not None:
            raise scan_holder["exc"]
        result = scan_holder["result"] or {}
        if not isinstance(result, dict):
            result = {}
        result["apk_name"] = filename or apk_path.name
        result["decompiled_summary"] = {
            "has_manifest": (out_dir / "AndroidManifest.xml").is_file(),
            "has_smali": any(out_dir.rglob("*.smali")),
            "has_java": any((out_dir / "sources").rglob("*.java")) if (out_dir / "sources").is_dir() else False,
        }
        yield _progress(99, "scan", "Scan finished - packaging mapper result.")
        yield _progress(100, "done", "Done.")
        yield {"type": "complete", "result": result}
    except Exception as e:
        yield {"type": "error", "message": f"SSL pinning map failed: {e}"}
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


@router.post("/map")
async def map_ssl_pinning(
    file: UploadFile = File(...),
    jadx_max_heap: Annotated[str | None, Form()] = None,
) -> dict:
    """
    Upload an APK/XAPK, decompile with Apktool (+ JADX when available), return pinning mapper JSON.
    """
    raw = await file.read()
    try:
        heap_arg = normalize_jadx_max_heap_arg(jadx_max_heap)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    result: dict | None = None
    err: str | None = None
    for ev in _ssl_pinning_events(raw, file.filename, jadx_max_heap=heap_arg):
        if ev.get("type") == "complete":
            result = ev.get("result")
        elif ev.get("type") == "error":
            err = ev.get("message", "Unknown error")
    if err:
        if err == "Upload too large":
            raise HTTPException(413, err)
        raise HTTPException(500, err)
    if not result:
        raise HTTPException(500, "SSL pinning map produced no result")
    return result


def _ndjson_bytes(events: Iterator[dict]) -> Iterator[bytes]:
    for ev in events:
        yield (json.dumps(ev, ensure_ascii=False) + "\n").encode("utf-8")


@router.post("/map-stream")
async def map_ssl_pinning_stream(
    file: UploadFile = File(...),
    jadx_max_heap: Annotated[str | None, Form()] = None,
) -> StreamingResponse:
    """
    Same pipeline as /map but streams NDJSON lines: progress events then a final complete or error.
    Optional form field jadx_max_heap (e.g. 4096m, 8g) sets JVM -Xmx for this run (overrides env and YAML default chain
    unless APPREDATOR_JADX_JAVA_OPTS is set on the server).
    """
    raw = await file.read()
    try:
        heap_arg = normalize_jadx_max_heap_arg(jadx_max_heap)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    def body() -> Iterator[bytes]:
        yield from _ndjson_bytes(_ssl_pinning_events(raw, file.filename, jadx_max_heap=heap_arg))

    return StreamingResponse(
        body(),
        media_type="application/x-ndjson; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )
