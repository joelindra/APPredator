"""
Generate a static HTML report from APPredator JSON (Jinja2).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.baseline_store import extract_application_id, fingerprint_finding


def _env() -> Environment:
    # core/reporting/html_report.py -> repo root -> templates/
    tpl_dir = Path(__file__).resolve().parent.parent.parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(tpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def report_to_html_string(
    report: dict[str, Any],
    *,
    baseline_fps: Optional[set[str]] = None,
) -> str:
    baseline_fps = baseline_fps or set()
    app_id = extract_application_id(report)
    results = []
    for item in report.get("results") or []:
        res = dict(item)
        rule_id = (item.get("vulnerability") or "rule").lower().replace(" ", "_")
        fp = fingerprint_finding(rule_id, item.get("file") or "", item.get("result") or {}, application_id=app_id)
        res["apppredator_fingerprint"] = fp
        res["apppredator_suppressed"] = fp in baseline_fps
        results.append(res)

    env = _env()
    tpl = env.get_template("report.html")
    return tpl.render(
        app_summary=report.get("app_summary"),
        attack_surface_map=report.get("attack_surface_map"),
        diff_summary=report.get("diff_summary") or {},
        exploit_validation=report.get("exploit_validation") or [],
        results=results,
    )


def write_html_file(report_path: str, out_path: str, baseline_fps: Optional[set[str]] = None) -> None:
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    html = report_to_html_string(data, baseline_fps=baseline_fps)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
