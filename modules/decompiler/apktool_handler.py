import os
import re
import shutil
import subprocess
from pathlib import Path

from core import log
from core.settings_io import resolve_tool_path

from .base import Decompiler

# aapt2 (Apktool b) rejects hex literals like 0x0 for gravity flag attrs — common after apktool d on some OEM apps.
_GRAVITY_HEX_ZERO_ATTRS = (
    "android:layout_gravity",
    "android:gravity",
    "android:foregroundGravity",
    "app:layout_gravity",
    "app:gravity",
    "tools:layout_gravity",
    "tools:gravity",
)
_GRAVITY_HEX_ZERO_RE = re.compile(
    "(" + "|".join(re.escape(a) for a in _GRAVITY_HEX_ZERO_ATTRS) + r")(\s*=\s*)(['\"])0x0+\3",
    re.IGNORECASE,
)


def sanitize_decoded_res_xml_for_aapt2(decoded_dir: str | os.PathLike[str]) -> tuple[int, int]:
    """
    Fix decoded XML so apktool b / aapt2 can link resources.

    Returns (files_modified, attribute_fixes).
    """
    root = Path(decoded_dir)
    res = root / "res"
    if not res.is_dir():
        return (0, 0)
    files_mod = 0
    fixes = 0
    for path in res.rglob("*.xml"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new_text, n = _GRAVITY_HEX_ZERO_RE.subn(
            lambda m: m.group(1) + m.group(2) + m.group(3) + "0" + m.group(3),
            text,
        )
        if n:
            fixes += n
            files_mod += 1
            try:
                path.write_text(new_text, encoding="utf-8", newline="")
            except OSError:
                continue
    return (files_mod, fixes)


class ApktoolHandler(Decompiler):
    def __init__(self, apktool_path: str = "apktool"):
        resolved = resolve_tool_path(apktool_path) if apktool_path else None
        self.apktool_path = resolved or apktool_path or "apktool"
        if not self._is_apktool_installed():
            raise FileNotFoundError(
                "Apktool is not installed or not in the system's PATH. "
                "Please install Apktool and ensure it is accessible."
            )

    def _is_apktool_installed(self) -> bool:
        p = self.apktool_path
        if shutil.which(p):
            return True
        return bool(p and os.path.isfile(p))

    def decompile(self, apk_path: str, output_dir: str):
        log.info(f"Starting decompilation of {apk_path} with Apktool...")
        framework_dir = "output/framework"
        os.makedirs(framework_dir, exist_ok=True)
        command = [
            self.apktool_path,
            "d",
            "-f",
            apk_path,
            "-o",
            output_dir,
            "-p",
            framework_dir,
        ]
        try:
            use_shell = os.name == "nt" and str(self.apktool_path).lower().endswith((".bat", ".cmd"))
            if use_shell:
                result = subprocess.run(
                    subprocess.list2cmdline(command),
                    check=True,
                    capture_output=True,
                    text=True,
                    shell=True,
                )
            else:
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            log.success(f"Successfully decompiled {apk_path} to {output_dir}")
            log.debug(f"Apktool Output:\n{result.stdout}")
        except FileNotFoundError:
            log.error(f"Error: '{self.apktool_path}' not found. Is Apktool installed and in your PATH?")
            raise
        except subprocess.CalledProcessError as e:
            log.error(f"An error occurred while running Apktool on {apk_path}.")
            log.error(f"Return Code: {e.returncode}")
            log.error(f"Output:\n{e.stderr}")
            raise

    def build(self, decoded_dir: str, output_apk: str) -> None:
        """Build a decoded Apktool project into an APK (unsigned until signed)."""
        log.info(f"Building APK from {decoded_dir} -> {output_apk}")
        decoded_abspath = os.path.abspath(decoded_dir)
        out_abspath = os.path.abspath(output_apk)
        os.makedirs(os.path.dirname(out_abspath) or ".", exist_ok=True)
        framework_dir = "output/framework"
        os.makedirs(framework_dir, exist_ok=True)
        n_files, n_fix = sanitize_decoded_res_xml_for_aapt2(decoded_abspath)
        if n_fix:
            log.info(f"Sanitized decoded res XML for aapt2 ({n_fix} gravity literal(s) in {n_files} file(s)).")
        command = [
            self.apktool_path,
            "b",
            decoded_abspath,
            "-o",
            out_abspath,
            "-p",
            framework_dir,
        ]
        try:
            use_shell = os.name == "nt" and str(self.apktool_path).lower().endswith((".bat", ".cmd"))
            if use_shell:
                result = subprocess.run(
                    subprocess.list2cmdline(command),
                    check=True,
                    capture_output=True,
                    text=True,
                    shell=True,
                )
            else:
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            log.success(f"Apktool build finished: {out_abspath}")
            log.debug(f"Apktool build output:\n{result.stdout}")
        except FileNotFoundError:
            log.error(f"Error: '{self.apktool_path}' not found during build.")
            raise
        except subprocess.CalledProcessError as e:
            log.error("Apktool build failed.")
            log.error(f"Return Code: {e.returncode}")
            log.error(f"Output:\n{e.stderr}")
            raise
