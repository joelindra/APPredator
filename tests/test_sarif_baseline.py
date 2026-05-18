import json

from core.baseline_store import (
    add_baseline_entry,
    delete_baseline_entry,
    fingerprint_finding,
    fingerprints_for_report,
    load_baselines,
    save_baselines,
)
from core.reporting.sarif import report_to_sarif
from core.scan_runner import evaluate_ci_gate


def test_fingerprint_stable():
    fp = fingerprint_finding(
        "sql_injection",
        "/tmp/Foo.smali",
        {"evidence": "SELECT", "description": "x"},
        application_id="com.example.app",
    )
    fp2 = fingerprint_finding(
        "sql_injection",
        "/tmp/Foo.smali",
        {"evidence": "SELECT", "description": "x"},
        application_id="com.example.app",
    )
    assert fp == fp2


def test_sarif_contains_runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "rep.json"
    report = {
        "app_summary": "package com.demo.test",
        "results": [
            {
                "file": "a.smali",
                "vulnerability": "SQL Injection",
                "status": "Vulnerable",
                "result": {"severity": "high", "description": "d", "is_vulnerable": True},
            }
        ],
    }
    p.write_text(json.dumps(report), encoding="utf-8")
    data = json.loads(p.read_text(encoding="utf-8"))
    sarif = report_to_sarif(data, baseline_ids=set())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1


def test_baseline_suppresses_in_sarif(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config/baselines").mkdir(parents=True)
    save_baselines([], path=tmp_path / "config/baselines/default.json")

    report = {
        "app_summary": "package com.demo.app",
        "results": [
            {
                "file": "x.smali",
                "vulnerability": "SQL Injection",
                "status": "Vulnerable",
                "result": {"severity": "medium", "description": "d", "evidence": "e"},
            }
        ],
    }
    fp = fingerprint_finding(
        "sql_injection",
        "x.smali",
        report["results"][0]["result"],
        application_id="com.demo.app",
    )
    add_baseline_entry(fp, "com.demo.app", "accepted", path=tmp_path / "config/baselines/default.json")

    fps = fingerprints_for_report(report, path=tmp_path / "config/baselines/default.json")
    assert fp in fps

    sarif = report_to_sarif(report, baseline_ids=fps)
    res0 = sarif["runs"][0]["results"][0]
    assert res0["properties"]["apppredator_suppressed"] is True

    entries = load_baselines(path=tmp_path / "config/baselines/default.json")
    delete_baseline_entry(entries[0]["id"], path=tmp_path / "config/baselines/default.json")
    assert load_baselines(path=tmp_path / "config/baselines/default.json") == []


def test_ci_gate(tmp_path):
    rep = tmp_path / "r.json"
    report = {
        "results": [
            {
                "file": "a.smali",
                "vulnerability": "SQL Injection",
                "status": "Vulnerable",
                "result": {"severity": "low", "description": "x"},
            }
        ]
    }
    rep.write_text(json.dumps(report), encoding="utf-8")
    fail, _ = evaluate_ci_gate(str(rep), fail_on_findings=False)
    assert fail is False
    fail2, _ = evaluate_ci_gate(str(rep), fail_on_findings=True, min_severity="high")
    assert fail2 is False
    fail3, _ = evaluate_ci_gate(str(rep), fail_on_findings=True)
    assert fail3 is True
