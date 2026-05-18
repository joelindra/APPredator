"""
Convert APPredator JSON report to SARIF 2.1.0.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from core.baseline_store import extract_application_id, fingerprint_finding


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _severity_to_level(severity: Optional[str]) -> str:
    s = (severity or "medium").lower()
    if s in ("critical", "high"):
        return "error"
    if s == "low":
        return "note"
    if s == "info":
        return "note"
    return "warning"


def report_to_sarif(
    report: dict[str, Any],
    *,
    tool_name: str = "apppredator",
    tool_version: str = "1.0.0",
    baseline_ids: Optional[set[str]] = None,
) -> dict[str, Any]:
    """
    baseline_ids: set of fingerprint strings to mark as suppressed (audit-friendly).
    """
    baseline_ids = baseline_ids or set()
    app_id = extract_application_id(report)
    results_out = []
    rules_index: dict[str, dict[str, Any]] = {}

    for item in report.get("results") or []:
        vuln_name = item.get("vulnerability") or "finding"
        rule_id = vuln_name.lower().replace(" ", "_")
        if rule_id not in rules_index:
            rules_index[rule_id] = {
                "id": rule_id,
                "name": vuln_name,
                "shortDescription": {"text": vuln_name},
            }

        res = item.get("result") or {}
        fp = fingerprint_finding(rule_id, item.get("file") or "", res, application_id=app_id)
        suppressed = fp in baseline_ids

        phys: dict[str, Any] = {
            "artifactLocation": {"uri": item.get("file") or "unknown"},
        }
        region: dict[str, Any] = {"startLine": 1}
        line_unknown = True
        if res.get("line") is not None:
            try:
                region["startLine"] = int(res["line"])
                line_unknown = False
            except (TypeError, ValueError):
                pass
        phys["region"] = region

        result_obj: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_level(res.get("severity")),
            "message": {"text": res.get("description") or item.get("status") or ""},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"apppredatorFingerprint": fp},
            "properties": {
                "apppredator_status": item.get("status"),
                "apppredator_line_unknown": line_unknown,
                "apppredator_suppressed": suppressed,
            },
        }
        if suppressed:
            result_obj["suppressions"] = [
                {"kind": "inSource", "justification": "Baseline / accepted risk"}
            ]
        results_out.append(result_obj)

    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://github.com/apppredator/apppredator",
                "rules": list(rules_index.values()),
            }
        },
        "results": results_out,
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def load_report_from_path(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_sarif_file(report_path: str, out_path: str, baseline_ids: Optional[set[str]] = None) -> None:
    data = load_report_from_path(report_path)
    sarif = report_to_sarif(data, baseline_ids=baseline_ids)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
