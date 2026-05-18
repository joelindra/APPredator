from core.finding_utils import enrich_result_common
from core.scan_history import diff_with_previous, record_scan


def test_enrich_result_adds_triage_and_compliance():
    out = enrich_result_common(
        file_path="src/MainActivity.java",
        vulnerability="SQL Injection",
        result={"severity": "high", "confidence": "low", "evidence": "rawQuery(userInput)"},
    )
    assert out["triage_level"] in {"critical_now", "review", "info"}
    assert out["owasp_mobile_top10"]
    assert out["remediation_summary"]
    assert out["fix_suggestion_template"]


def test_scan_history_diff_by_apk_version(tmp_path):
    history = tmp_path / "scan_history.json"
    old_results = [
        {
            "file": "a.smali",
            "vulnerability": "SQL Injection",
            "status": "Vulnerable",
            "result": {"evidence": "q1"},
        }
    ]
    new_results = [
        {
            "file": "a.smali",
            "vulnerability": "SQL Injection",
            "status": "Vulnerable",
            "result": {"evidence": "q1"},
        },
        {
            "file": "b.smali",
            "vulnerability": "Intent Spoofing",
            "status": "Vulnerable",
            "result": {"evidence": "q2"},
        },
    ]
    record_scan(
        apk_version="app-v1.apk",
        application_id="com.demo.app",
        report_path="out-v1.json",
        results=old_results,
        path=history,
    )
    diff = diff_with_previous(
        apk_version="app-v2.apk",
        application_id="com.demo.app",
        results=new_results,
        path=history,
    )
    assert diff["new_count"] == 1
    assert diff["resolved_count"] == 0
    assert diff["unchanged_count"] == 1
