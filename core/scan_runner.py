"""
Shared scan entrypoint for CLI (``apppredator analyze`` / ``python -m apppredator.cli``) and the web API.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from core.config_loader import Settings, load_settings
from core.engine import Engine
from core import log


@dataclass
class ScanFlags:
    output: Optional[str] = None
    no_decompile: bool = False
    rules: Optional[str] = None
    profile: Optional[str] = None
    generate_exploit: bool = False
    scan_libraries: bool = False


@dataclass
class ScanResult:
    success: bool
    output_json_path: Optional[str] = None
    exploit_dir: Optional[str] = None
    error: Optional[str] = None
    findings_summary: dict[str, Any] = field(default_factory=dict)


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> None:
    for key, val in overrides.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def merge_settings(base: Settings, overrides: Optional[dict[str, Any]]) -> Settings:
    if not overrides:
        return base
    data = base.model_dump()
    _deep_merge(data, overrides)
    return Settings(**data)


def run_scan(
    apk_path: str,
    flags: ScanFlags,
    settings_overrides: Optional[dict[str, Any]] = None,
    on_partial_results: Optional[Callable[[list[dict[str, Any]]], None]] = None,
) -> ScanResult:
    """
    Run a full scan. Uses cwd-relative paths (config/, output/) like the CLI.
    """
    if not os.path.isfile(apk_path):
        return ScanResult(success=False, error=f"APK not found: {apk_path}")

    try:
        settings = load_settings(flags.profile)
        settings = merge_settings(settings, settings_overrides)

        if flags.generate_exploit:
            settings.analysis.generate_exploit = True
        if flags.scan_libraries:
            settings.analysis.scan_libraries = True
            log.info("Library Hunter Mode: ENABLED")

        engine = Engine(settings, on_partial_results=on_partial_results)
        engine.run(apk_path, flags.output, flags.no_decompile, flags.rules)

        out_path = getattr(engine, "final_output_file", None)
        exploit_dir = getattr(engine, "final_exploit_dir", None)
        summary = _summarize_report(out_path)

        return ScanResult(
            success=True,
            output_json_path=out_path,
            exploit_dir=exploit_dir,
            findings_summary=summary,
        )
    except Exception as e:
        log.error(f"Scan failed: {e}")
        return ScanResult(success=False, error=str(e))


def _summarize_report(json_path: Optional[str]) -> dict[str, Any]:
    if not json_path or not os.path.isfile(json_path):
        return {"vulnerable_count": 0, "total_results": 0}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"vulnerable_count": 0, "total_results": 0}

    results = data.get("results") or []
    vuln = sum(1 for r in results if r.get("status") == "Vulnerable")
    return {"vulnerable_count": vuln, "total_results": len(results)}


def severity_rank(sev: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get((sev or "").lower(), 0)


def evaluate_ci_gate(
    json_path: str,
    *,
    fail_on_findings: bool,
    min_severity: Optional[str] = None,
    ignore_rules: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """
    Returns (should_fail, message). should_fail True means exit code should be non-zero.

    ignore_rules: vulnerability display names (or substrings) to exclude from the gate.
    min_severity: only findings at or above this severity count (e.g. High).
    """
    if not fail_on_findings:
        return False, "CI gate disabled"

    if not os.path.isfile(json_path):
        return True, f"Report not found: {json_path}"

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results") or []
    ignore = [x.lower() for x in (ignore_rules or [])]
    min_r = severity_rank(min_severity) if min_severity else 0

    violations: list[str] = []
    for item in results:
        if item.get("status") != "Vulnerable":
            continue
        vuln_name = (item.get("vulnerability") or "").lower()
        if ignore and any(ign in vuln_name for ign in ignore):
            continue
        res = item.get("result") or {}
        sev = res.get("severity") or "medium"
        if severity_rank(sev) < min_r:
            continue
        violations.append(f"{item.get('vulnerability')} @ {item.get('file')} ({sev})")

    if violations:
        return True, "CI gate failed: " + "; ".join(violations[:20]) + (
            f" ... (+{len(violations) - 20} more)" if len(violations) > 20 else ""
        )
    return False, "CI gate passed"
