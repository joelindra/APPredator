from __future__ import annotations

import hashlib
from typing import Any


SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

CONFIDENCE_ORDER: dict[str, int] = {
    "very_high": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "very_low": 1,
    "unknown": 0,
}

OWASP_MOBILE_TOP10_MAP: dict[str, str] = {
    "sql_injection": "M9: Reverse Engineering",
    "webview_xss": "M7: Client Code Quality",
    "hardcoded_secrets": "M5: Insufficient Cryptography",
    "hardcoded_secrets_xml": "M5: Insufficient Cryptography",
    "insecure_storage": "M2: Inadequate Supply Chain Security",
    "insecure_file_permissions": "M6: Inadequate Privacy Controls",
    "webview_deeplink": "M1: Improper Credential Usage",
    "deeplink_hijack": "M3: Insecure Authentication/Authorization",
    "deeplink_logic_bypass": "M3: Insecure Authentication/Authorization",
    "intent_spoofing": "M3: Insecure Authentication/Authorization",
    "exported_components": "M1: Improper Credential Usage",
    "insecure_random_number_generation": "M5: Insufficient Cryptography",
    "insecure_deserialization": "M7: Client Code Quality",
    "unsafe_reflection": "M7: Client Code Quality",
    "path_traversal": "M7: Client Code Quality",
    "zip_slip": "M7: Client Code Quality",
    "fragment_injection": "M7: Client Code Quality",
}

REMEDIATION_TEMPLATES: dict[str, str] = {
    "java": "Validate untrusted input at boundaries, enforce allowlist checks, and fail closed. Add unit test for vulnerable path.",
    "kotlin": "Use sealed validation flow for external input, reject unexpected states early, and add regression test for attack scenario.",
    "smali": "Trace source-to-sink path, add explicit guard before sink invocation, and verify class/component export visibility flags.",
    "generic": "Validate external input, enforce authorization checks, and add regression test proving exploit path is blocked.",
}


def normalize_text(value: Any, *, max_len: int = 1200) -> str:
    s = str(value or "").strip()
    return s[:max_len]


def normalize_severity(value: Any) -> str:
    s = normalize_text(value, max_len=32).lower()
    if s in SEVERITY_ORDER:
        return s
    aliases = {
        "informational": "info",
        "moderate": "medium",
        "med": "medium",
    }
    return aliases.get(s, "unknown")


def normalize_confidence(value: Any) -> str:
    s = normalize_text(value, max_len=32).lower().replace(" ", "_")
    if s in CONFIDENCE_ORDER:
        return s
    aliases = {
        "certain": "very_high",
        "strong": "high",
        "moderate": "medium",
        "weak": "low",
    }
    return aliases.get(s, "unknown")


def calibrated_confidence(raw_confidence: Any, *, severity: str, has_evidence: bool) -> str:
    conf = normalize_confidence(raw_confidence)
    score = CONFIDENCE_ORDER.get(conf, 0)
    sev_score = SEVERITY_ORDER.get(normalize_severity(severity), 0)
    if has_evidence and score < 4:
        score += 1
    if sev_score >= 4 and score < 3:
        score += 1
    score = max(0, min(score, 5))
    reverse = {v: k for k, v in CONFIDENCE_ORDER.items()}
    return reverse.get(score, "unknown")


def finding_priority_score(result: dict[str, Any]) -> int:
    sev = normalize_severity(result.get("severity"))
    conf = normalize_confidence(result.get("confidence"))
    return (SEVERITY_ORDER.get(sev, 0) * 10) + CONFIDENCE_ORDER.get(conf, 0)


def triage_level(result: dict[str, Any], vuln_name: str = "") -> tuple[str, str]:
    sev = normalize_severity(result.get("severity"))
    conf = normalize_confidence(result.get("confidence"))
    score = finding_priority_score({"severity": sev, "confidence": conf})
    vuln_norm = normalize_text(vuln_name, max_len=128).lower()
    high_signal = any(
        x in vuln_norm
        for x in ("exported", "auth", "spoof", "hijack", "injection", "deserialization")
    )

    if score >= 44 or (high_signal and score >= 34):
        return "critical_now", "High severity/confidence or exploit-prone pattern."
    if score >= 24:
        return "review", "Needs analyst validation before patch planning."
    return "info", "Low confidence or low severity context."


def remediation_template_for_file(file_path: str) -> str:
    p = normalize_text(file_path, max_len=300).lower()
    if p.endswith(".java"):
        return REMEDIATION_TEMPLATES["java"]
    if p.endswith(".kt"):
        return REMEDIATION_TEMPLATES["kotlin"]
    if p.endswith(".smali"):
        return REMEDIATION_TEMPLATES["smali"]
    return REMEDIATION_TEMPLATES["generic"]


def canonical_finding_key(
    *,
    file_path: str,
    vulnerability: str,
    status: str,
    evidence: str,
) -> str:
    normalized_file = normalize_text(file_path, max_len=600).replace("\\", "/").lower()
    normalized_vuln = normalize_text(vulnerability, max_len=160).lower()
    normalized_status = normalize_text(status, max_len=32).lower()
    evidence_hash = hashlib.sha256(normalize_text(evidence, max_len=500).encode("utf-8", errors="ignore")).hexdigest()[:20]
    return f"{normalized_file}|{normalized_vuln}|{normalized_status}|{evidence_hash}"


def enrich_result_common(
    *,
    file_path: str,
    vulnerability: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    out = dict(result or {})
    sev = normalize_severity(out.get("severity"))
    evidence = normalize_text(out.get("evidence"))
    cal_conf = calibrated_confidence(out.get("confidence"), severity=sev, has_evidence=bool(evidence))
    out["severity"] = sev
    out["confidence"] = cal_conf
    triage, reason = triage_level(out, vulnerability)
    out["triage_level"] = triage
    out["triage_reason"] = reason
    rule_id = normalize_text(vulnerability, max_len=128).lower().replace(" ", "_")
    out["owasp_mobile_top10"] = OWASP_MOBILE_TOP10_MAP.get(rule_id, "M7: Client Code Quality")
    out["remediation_summary"] = out.get("recommendation") or remediation_template_for_file(file_path)
    out["fix_suggestion_template"] = remediation_template_for_file(file_path)
    return out
