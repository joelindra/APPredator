import os
import re
import shutil
import subprocess
from pathlib import Path

from core import log
from core.settings_io import resolve_tool_path

_JADX_XMX_RE = re.compile(r"^[1-9]\d{0,5}[kmg]?$")


def normalize_jadx_max_heap_arg(value: str | None) -> str | None:
    """
    Validate optional -Xmx value from UI or YAML (e.g. 4096m, 8g, 512k).
    Returns None if empty. Raises ValueError if malformed.
    """
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    if not _JADX_XMX_RE.match(s):
        raise ValueError(
            "Invalid JADX heap; use digits with optional suffix k, m, or g (examples: 4096m, 6g, 8192k)."
        )
    return s


def resolved_jadx_max_heap(
    *,
    max_heap_override: str | None = None,
    max_heap_from_settings: str | None = None,
) -> str:
    """
    Effective -Xmx string for logging/UI (does not apply APPREDATOR_JADX_JAVA_OPTS override).
    Precedence: per-request override > env APPREDATOR_JADX_MAX_HEAP > settings YAML > default 4096m.
    """
    o = (max_heap_override or "").strip().lower()
    e = (os.environ.get("APPREDATOR_JADX_MAX_HEAP") or "").strip().lower()
    c = (max_heap_from_settings or "").strip().lower()
    return o or e or c or "4096m"


def jadx_subprocess_env(
    *,
    max_heap_from_settings: str | None = None,
    max_heap_override: str | None = None,
) -> dict:
    """
    JVM options for the JADX child process.

    - APPREDATOR_JADX_JAVA_OPTS: if set, used as JAVA_TOOL_OPTIONS for this subprocess only (full override).
    - Else -Xmx from max_heap_override (e.g. web UI for this run), then APPREDATOR_JADX_MAX_HEAP,
      then YAML jadx.max_heap, then default 4096m.
    - Merges with any existing JAVA_TOOL_OPTIONS in the parent environment (appended after our -Xmx).
    """
    env = os.environ.copy()
    override = os.environ.get("APPREDATOR_JADX_JAVA_OPTS", "").strip()
    if override:
        env["JAVA_TOOL_OPTIONS"] = override
        return env
    max_heap = resolved_jadx_max_heap(
        max_heap_override=max_heap_override,
        max_heap_from_settings=max_heap_from_settings,
    )
    # Explicit cap avoids HotSpot default large heap / mmap failures on small page files.
    heap_opts = f"-Xmx{max_heap} -Xms128m -XX:+UseG1GC -XX:MaxHeapFreeRatio=40"
    prev = env.get("JAVA_TOOL_OPTIONS", "").strip()
    env["JAVA_TOOL_OPTIONS"] = f"{heap_opts} {prev}".strip() if prev else heap_opts
    return env


def _resolve_jadx_path(jadx_path: str | None) -> str | None:
    """
    Resolve configured jadx path to an absolute .bat/.exe so Windows cmd (shell=True) does not
    misparse `tools/...` as switches. Do not return a cwd-relative `tools\\...` path even if
    os.path.isfile(raw) is true - that breaks subprocess when cwd differs from repo root.
    """
    if not jadx_path or not str(jadx_path).strip():
        return shutil.which("jadx")
    raw = str(jadx_path).strip()

    normalized = resolve_tool_path(raw)
    if normalized and os.path.isfile(normalized):
        return normalized

    w = shutil.which(raw)
    if w:
        return w
    if raw and os.path.isfile(raw):
        return str(Path(raw).resolve())
    return shutil.which("jadx")


class JadxHandler:
    def __init__(self, jadx_path: str | None = None, max_heap: str | None = None):
        self.jadx_path = _resolve_jadx_path(jadx_path)
        self._max_heap = (max_heap or "").strip() or None

        if not self.jadx_path:
            log.warning("JADX not found in PATH or configuration. Please install JADX to use Java source code analysis.")

    def is_available(self) -> bool:
        return self.jadx_path is not None

    def decompile(self, apk_path: str, output_dir: str, *, max_heap_override: str | None = None) -> bool:
        """
        Decompiles the APK using JADX to the specified output directory.

        max_heap_override: optional -Xmx value for this invocation only (e.g. from SSL Pinning Mapper web UI).
        """
        if not self.is_available():
            log.error("Cannot decompile with JADX: Tool not found.")
            return False

        apk_abspath = os.path.abspath(apk_path)
        output_abspath = os.path.abspath(output_dir)

        if not os.path.exists(apk_abspath):
            log.error(f"APK file not found: {apk_abspath}")
            return False

        # Create output directory if it doesn't exist
        os.makedirs(output_abspath, exist_ok=True)

        log.info(f"Decompiling {apk_abspath} with JADX...")
        log.debug(
            "JADX child JVM heap via JAVA_TOOL_OPTIONS "
            "(APPREDATOR_JADX_JAVA_OPTS overrides all; else per-run override, APPREDATOR_JADX_MAX_HEAP, "
            "settings jadx.max_heap, default 4096m)."
        )

        try:
            # Removed --no-res and --no-assets as they are not standard JADX CLI flags or vary by version.
            # We let JADX handle resources (it puts them in 'resources' folder usually).
            cmd = [self.jadx_path, "-d", output_abspath, apk_abspath]

            # Log command for debugging
            log.debug(f"Executing command: {' '.join(cmd)}")

            jadx_env = jadx_subprocess_env(
                max_heap_from_settings=self._max_heap,
                max_heap_override=max_heap_override,
            )
            use_shell = os.name == "nt" and str(self.jadx_path).lower().endswith((".bat", ".cmd"))
            if use_shell:
                result = subprocess.run(
                    subprocess.list2cmdline(cmd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    shell=True,
                    env=jadx_env,
                )
            else:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    env=jadx_env,
                )
            
            # Check if output directory has content (specifically 'sources' which Jadx makes)
            sources_path = os.path.join(output_abspath, "sources")
            has_sources = os.path.exists(sources_path) and os.listdir(sources_path)
            
            if result.returncode == 0:
                log.success(f"JADX decompilation successful: {output_abspath}")
                return True
            elif has_sources:
                # JADX often exits 1 when some classes cannot be decompiled (obfuscation, bytecode edge cases).
                # As long as sources/ exists, downstream scans can use partial Java + Apktool Smali.
                combined = "\n".join(filter(None, [result.stderr or "", result.stdout or ""]))
                err_summary = None
                for raw in combined.splitlines():
                    low = raw.lower()
                    if "finished with errors" in low or (
                        "error" in low and "count" in low and "finished" in low
                    ):
                        err_summary = raw.strip()
                        break
                if err_summary:
                    log.info(
                        f"JADX: {err_summary} - partial Java only; Smali from Apktool remains complete. "
                        "This is normal for hardened APKs."
                    )
                else:
                    log.info(
                        f"JADX exited with code {result.returncode} but wrote sources/ - continuing "
                        "(typical when some classes fail to decompile; see debug logs for JADX output)."
                    )
                log.debug(f"JADX STDOUT: {result.stdout}")
                log.debug(f"JADX STDERR: {result.stderr}")
                return True
            else:
                log.error(f"JADX failed with exit code {result.returncode} and no sources found.")
                log.error(f"STDOUT: {result.stdout}")
                log.error(f"STDERR: {result.stderr}")
                combined_oom = "\n".join(filter(None, [result.stdout or "", result.stderr or ""]))
                if "OutOfMemoryError" in combined_oom or "java heap space" in combined_oom.lower():
                    log.warning(
                        "JADX ran out of Java heap. Raise memory: use SSL Pinning Mapper JADX heap field or "
                        "settings jadx.max_heap / APPREDATOR_JADX_MAX_HEAP (e.g. 8192m), or set APPREDATOR_JADX_JAVA_OPTS "
                        "for a full JAVA_TOOL_OPTIONS string. Then retry the decompile."
                    )
                return False

        except Exception as e:
            log.error(f"An unexpected error occurred during JADX decompilation: {e}")
            return False
