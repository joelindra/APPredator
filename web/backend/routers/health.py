from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from fastapi import APIRouter

from core.config_loader import load_settings
from core.settings_io import DEFAULT_SETTINGS_PATH, resolve_tool_path

router = APIRouter(prefix="/api/health", tags=["health"])


def _which_version(cmd: list[str], timeout: float = 5.0) -> dict[str, Any]:
    try:
        # Windows: .bat/.cmd are not valid CreateProcess images; run via shell when needed.
        use_shell = False
        if os.name == "nt" and cmd and str(cmd[0]).lower().endswith((".bat", ".cmd")):
            use_shell = True
        if use_shell:
            r = subprocess.run(
                subprocess.list2cmdline(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True,
            )
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr or "").strip()[:500]}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return {"ok": False, "output": str(e)}


def _ubersigner_health(jar_path: str, timeout: float = 12.0) -> dict[str, Any]:
    """uber-apk-signer: use -v (short); UI shows semver only, not full --help text."""
    try:
        use_shell = os.name == "nt" and str(jar_path).lower().endswith((".bat", ".cmd"))
        cmd = ["java", "-jar", str(jar_path), "-v"]
        if use_shell:
            r = subprocess.run(
                subprocess.list2cmdline(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True,
            )
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        blob = (r.stdout or "") + ("\n" if r.stdout and r.stderr else "") + (r.stderr or "")
        text = blob.strip()
        if r.returncode != 0 and not text:
            return {"ok": False, "output": f"exit {r.returncode}"}
        for line in text.splitlines():
            s = line.strip()
            if s.lower().startswith("version:"):
                ver = s.split(":", 1)[1].strip()
                return {"ok": r.returncode == 0, "output": ver or s}
        first = text.splitlines()[0].strip() if text else ""
        if first and r.returncode == 0:
            return {"ok": True, "output": first}
        return {"ok": r.returncode == 0, "output": (text or "no output")[:200]}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return {"ok": False, "output": str(e)}


def _resolve_cmd(env_key: str, fallback: str, settings_path: str | None) -> str:
    preferred = (os.environ.get(env_key) or "").strip()
    if preferred and (shutil.which(preferred) or os.path.isfile(preferred)):
        return preferred
    if shutil.which(fallback):
        return fallback
    if settings_path and os.path.isfile(settings_path):
        return settings_path
    return fallback


@router.get("")
def health() -> dict[str, Any]:
    java = _which_version(["java", "-version"])

    apktool_cfg: str | None = None
    jadx_cfg: str | None = None
    ubersigner_jar: str | None = None
    provider = None
    try:
        s = load_settings()
        provider = s.llm.provider
        apktool_raw = (s.apktool.path or "").strip() or None
        apktool_cfg = resolve_tool_path(apktool_raw) if apktool_raw else None
        if s.jadx and s.jadx.path:
            jx = (s.jadx.path or "").strip() or None
            jadx_cfg = resolve_tool_path(jx) if jx else None
        u_raw = (s.ubersigner.jar_path if s.ubersigner else None) or ""
        ubersigner_jar = resolve_tool_path(u_raw.strip() or "tools/signer/ubersigner.jar")
    except Exception as e:
        provider = f"error: {e}"
        ubersigner_jar = resolve_tool_path("tools/signer/ubersigner.jar")

    apktool_bin = _resolve_cmd("APKTOOL_PATH", "apktool", apktool_cfg)
    apktool = _which_version([apktool_bin, "--version"])
    jadx_bin = _resolve_cmd("JADX_PATH", "jadx", jadx_cfg)
    jadx = _which_version([jadx_bin, "--version"])

    ubersigner: dict[str, Any]
    if ubersigner_jar and os.path.isfile(ubersigner_jar):
        ubersigner = _ubersigner_health(ubersigner_jar)
    else:
        ubersigner = {"ok": False, "output": f"JAR not found: {ubersigner_jar}"}

    return {
        "status": "ok",
        "java": java,
        "apktool": apktool,
        "jadx": jadx,
        "ubersigner": ubersigner,
        "llm_provider": provider,
        "settings_path": str(DEFAULT_SETTINGS_PATH),
    }


@router.get("/deep")
def health_deep() -> dict[str, Any]:
    """Same as /api/health plus resolved settings path existence."""
    h = health()
    h["settings_file_exists"] = DEFAULT_SETTINGS_PATH.is_file()
    return h


def _env_set(name: str) -> bool:
    return bool((os.environ.get(name) or "").strip())


@router.get("/server-tuning")
def server_tuning() -> dict[str, Any]:
    """Non-secret snapshot of server-side knobs (set in environment / process)."""
    return {
        "items": [
            {
                "name": "APPREDATOR_CORS_ORIGINS",
                "description": "Comma-separated browser origins allowed for CORS.",
                "configured": _env_set("APPREDATOR_CORS_ORIGINS"),
            },
            {
                "name": "APPREDATOR_MAX_UPLOAD_MB",
                "description": "Max APK upload size (default 512).",
                "configured": _env_set("APPREDATOR_MAX_UPLOAD_MB"),
            },
            {
                "name": "APPREDATOR_SETTINGS_PATH",
                "description": "Alternate path to settings.yaml.",
                "configured": _env_set("APPREDATOR_SETTINGS_PATH"),
            },
            {
                "name": "APPREDATOR_BASELINE_PATH",
                "description": "Alternate path to baselines JSON.",
                "configured": _env_set("APPREDATOR_BASELINE_PATH"),
            },
            {
                "name": "DEEPSEEK_API_KEY",
                "description": "Fallback if llm.deepseek_api_key is empty in YAML.",
                "configured": _env_set("DEEPSEEK_API_KEY"),
            },
        ]
    }
