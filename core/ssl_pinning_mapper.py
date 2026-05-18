"""
Static SSL / certificate pinning mapper for decompiled Android trees (Apktool/JADX output).

Detects common stacks (OkHttp, TrustKit, Cronet, Flutter hooks, Network Security Config)
and emits locations, language hints, a simple trust-flow graph, and a starter Frida script.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class PinningHit:
    library: str
    display_name: str
    mechanism: str
    file_path: str
    language: str
    line_number: Optional[int] = None
    evidence: str = ""
    confidence: str = "medium"


# (library_id, display_name, mechanism, regex flags)
_RULES: list[tuple[str, str, str, str]] = [
    (
        "okhttp",
        "OkHttp",
        "CertificatePinner / OkHttp TLS stack",
        r"okhttp3[/\\]CertificatePinner|Lokhttp3/CertificatePinner|CertificatePinner\.Builder|\.check\(\s*Ljava/lang/String;",
    ),
    (
        "okhttp",
        "OkHttp",
        "HostnameVerifier / custom verifier",
        r"javax[/\\]net[/\\]ssl[/\\]HostnameVerifier|HostnameVerifier;->verify\(|CertificateChainCleaner",
    ),
    (
        "trustkit",
        "TrustKit",
        "TrustKit pinning / SSLSocketFactory",
        r"com[/\\]datatheorem[/\\]android[/\\]trustkit|TrustKit\.init|pinning_validation_report",
    ),
    (
        "cronet",
        "Cronet",
        "Cronet engine / certificate verifier",
        r"org[/\\]chromium[/\\]net[/\\]CronetEngine|CronetProvider|ExperimentalCronetEngine|UrlRequest\.Builder",
    ),
    (
        "flutter",
        "Flutter / Dart plugin",
        "Flutter embedding or pinning-related plugin",
        r"io[/\\]flutter[/\\]embedding|flutter_secure_storage|SslPinning|badCertificateCallback|HttpOverrides",
    ),
    (
        "conscrypt",
        "Conscrypt / platform TLS",
        "Conscrypt TrustManager / platform",
        r"org[/\\]conscrypt|PlatformTrustManager|TrustManagerImpl|X509TrustManagerExtensions",
    ),
    (
        "retrofit",
        "Retrofit",
        "Retrofit client (often paired with OkHttp pinning)",
        r"retrofit2[/\\]Retrofit|Retrofit\.Builder",
    ),
    (
        "bouncycastle",
        "BouncyCastle",
        "BC PKIX / cert path (custom chain building)",
        r"org[/\\]bouncycastle[/\\]jsse|org[/\\]bouncycastle[/\\]cert\.jcajce|BCSSLParameters",
    ),
    (
        "webview",
        "WebView TLS",
        "WebViewClient SSL error handler (custom trust)",
        r"WebViewClient;->onReceivedSslError|SslErrorHandler;->proceed\(",
    ),
]

_MANIFEST_NSC = re.compile(
    r"android:networkSecurityConfig\s*=\s*\"@xml/([^\"]+)\"|networkSecurityConfig\s*=\s*\"@xml/([^\"]+)\"",
    re.I,
)

_PINSET = re.compile(r"<pin-set|<pin\b[^>]*digest=", re.I)


def _lang_for_path(p: Path) -> str:
    s = p.suffix.lower()
    if s == ".smali":
        return "smali"
    if s == ".java":
        return "java"
    if s == ".kt":
        return "kotlin"
    if s == ".xml":
        return "xml"
    if s in (".c", ".cpp", ".h", ".cc"):
        return "native_source"
    return "other"


def _read_text_safe(path: Path, max_bytes: int = 1_500_000) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
    except OSError:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _line_for_match(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def analyze_decompiled_tree(decompiled_root: str | Path) -> dict[str, Any]:
    root = Path(decompiled_root).resolve()
    hits: list[PinningHit] = []
    seen: set[tuple[str, str, str]] = set()

    # Walk text sources
    exts = {".smali", ".java", ".kt"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        text = _read_text_safe(path)
        if not text:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        lang = _lang_for_path(path)
        for lib_id, disp, mech, pat in _RULES:
            rx = re.compile(pat)
            for m in rx.finditer(text):
                key = (lib_id, rel, m.group(0)[:120])
                if key in seen:
                    continue
                seen.add(key)
                line = _line_for_match(text, m.start())
                snippet = text[max(0, m.start() - 40) : m.end() + 80].replace("\n", " ").strip()
                hits.append(
                    PinningHit(
                        library=lib_id,
                        display_name=disp,
                        mechanism=mech,
                        file_path=rel,
                        language=lang,
                        line_number=line,
                        evidence=snippet[:400],
                        confidence="high" if lib_id in ("okhttp", "trustkit", "cronet") else "medium",
                    )
                )

    # AndroidManifest.xml → network security config reference
    manifest = root / "AndroidManifest.xml"
    nsc_files: list[str] = []
    if manifest.is_file():
        mtext = _read_text_safe(manifest, max_bytes=400_000) or ""
        for m in _MANIFEST_NSC.finditer(mtext):
            name = next((g for g in m.groups() if g), None)
            if not name:
                continue
            # @xml/foo -> res/xml/foo.xml
            candidates = [
                root / "res" / "xml" / f"{name}.xml",
                root / "res" / "xml" / name,
            ]
            for c in candidates:
                if c.is_file():
                    rel = str(c.relative_to(root)).replace("\\", "/")
                    if rel not in nsc_files:
                        nsc_files.append(rel)
                    xtxt = _read_text_safe(c) or ""
                    if _PINSET.search(xtxt):
                        key = ("nsc", rel, "pin-set")
                        if key not in seen:
                            seen.add(key)
                            hits.append(
                                PinningHit(
                                    library="network_security_config",
                                    display_name="Network Security Config",
                                    mechanism="XML pin-set / domain-config pinning",
                                    file_path=rel,
                                    language="xml",
                                    line_number=None,
                                    evidence=_PINSET.search(xtxt).group(0)[:200] if _PINSET.search(xtxt) else "",
                                    confidence="high",
                                )
                            )
                    break

    # Scan all res/xml for embedded pin-set without manifest link (heuristic)
    xml_dir = root / "res" / "xml"
    if xml_dir.is_dir():
        for x in xml_dir.glob("*.xml"):
            rel = str(x.relative_to(root)).replace("\\", "/")
            if rel in nsc_files:
                continue
            xtxt = _read_text_safe(x) or ""
            if _PINSET.search(xtxt):
                key = ("nsc_loose", rel, "pin")
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    PinningHit(
                        library="network_security_config",
                        display_name="Network Security Config",
                        mechanism="Pin definitions in res/xml (manifest link not resolved here)",
                        file_path=rel,
                        language="xml",
                        evidence="pin-set or pin digest found",
                        confidence="medium",
                    )
                )

    # Native libs present (ABI folders)
    native_libs: list[str] = []
    lib_root = root / "lib"
    if lib_root.is_dir():
        for so in lib_root.rglob("*.so"):
            try:
                rel = str(so.relative_to(root)).replace("\\", "/")
                native_libs.append(rel)
            except ValueError:
                continue

    # JNI loadLibrary hints in smali for ssl-related .so names
    ssl_native_hints: list[str] = []
    ssl_so_tokens = ("ssl", "crypto", "conscrypt", "boringssl", "cronet")
    for path in root.rglob("*.smali"):
        t = _read_text_safe(path, max_bytes=400_000)
        if not t:
            continue
        if "loadLibrary" not in t:
            continue
        low = t.lower()
        if any(tok in low for tok in ssl_so_tokens):
            rel = str(path.relative_to(root)).replace("\\", "/")
            if rel not in ssl_native_hints:
                ssl_native_hints.append(rel)

    # Aggregate libraries
    lib_counts: dict[str, int] = {}
    for h in hits:
        lib_counts[h.library] = lib_counts.get(h.library, 0) + 1

    libraries_ranked = sorted(lib_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    libraries_detected = [
        {
            "id": lid,
            "hits": cnt,
            "label": next((x.display_name for x in hits if x.library == lid), lid),
        }
        for lid, cnt in libraries_ranked
    ]

    lang_counts: dict[str, int] = {}
    for h in hits:
        lang_counts[h.language] = lang_counts.get(h.language, 0) + 1
    if native_libs:
        lang_counts["native_binary"] = len(native_libs)

    trust_nodes, trust_edges = _build_trust_flow(hits, bool(native_libs))
    mermaid = _trust_flow_mermaid(trust_nodes, trust_edges)
    frida = _build_frida_script(hits, libraries_ranked)

    return {
        "libraries_detected": libraries_detected,
        "locations": [
            {
                "library": h.library,
                "display_name": h.display_name,
                "mechanism": h.mechanism,
                "file": h.file_path,
                "language": h.language,
                "line": h.line_number,
                "confidence": h.confidence,
                "evidence": h.evidence,
            }
            for h in hits
        ],
        "language_summary": lang_counts,
        "native_libraries_sample": sorted(native_libs)[:80],
        "native_library_total": len(native_libs),
        "native_smali_hints": ssl_native_hints[:40],
        "trust_flow": {"nodes": trust_nodes, "edges": trust_edges},
        "trust_flow_mermaid": mermaid,
        "frida_script": frida,
        "notes": [
            "Static heuristics only — obfuscation or dynamic loading may hide real pinning.",
            "Review Network Security Config XML and OkHttp CertificatePinner builders manually.",
            "Frida script is a starting point; adjust class names and multi-dex obfuscation as needed.",
        ],
    }


def _build_trust_flow(
    hits: list[PinningHit],
    has_native: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    nodes = [{"id": "app", "label": "Application", "kind": "app"}]
    edges: list[dict[str, str]] = []

    libs_present = {h.library for h in hits}
    if "okhttp" in libs_present:
        nodes += [
            {"id": "okhttp", "label": "OkHttp client", "kind": "transport"},
            {"id": "okhttp_pin", "label": "CertificatePinner / verifiers", "kind": "pinning"},
        ]
        edges += [
            {"from": "app", "to": "okhttp", "label": "HTTP"},
            {"from": "okhttp", "to": "okhttp_pin", "label": "pin checks"},
        ]
    if "trustkit" in libs_present:
        nodes += [{"id": "trustkit", "label": "TrustKit", "kind": "pinning"}]
        edges.append({"from": "app", "to": "trustkit", "label": "SSLSocketFactory / pinning"})
    if "cronet" in libs_present:
        nodes += [{"id": "cronet", "label": "Cronet", "kind": "transport"}]
        edges.append({"from": "app", "to": "cronet", "label": "CronetEngine"})
    if "flutter" in libs_present:
        nodes += [{"id": "flutter", "label": "Flutter engine / plugins", "kind": "transport"}]
        edges.append({"from": "app", "to": "flutter", "label": "Dart/embedding"})
    if "network_security_config" in libs_present:
        nodes += [{"id": "nsc", "label": "Network Security Config", "kind": "policy"}]
        edges.append({"from": "app", "to": "nsc", "label": "manifest"})
    if "conscrypt" in libs_present or "bouncycastle" in libs_present:
        nodes += [{"id": "tls_stack", "label": "Custom TLS / Conscrypt / BC", "kind": "tls"}]
        edges.append({"from": "app", "to": "tls_stack", "label": "TrustManager chain"})

    nodes.append({"id": "trust_anchor", "label": "Server certs / pin digests", "kind": "remote"})
    for n in nodes:
        nid = n["id"]
        if nid in ("app", "trust_anchor"):
            continue
        if not any(e.get("from") == nid and e.get("to") == "trust_anchor" for e in edges):
            edges.append({"from": nid, "to": "trust_anchor", "label": "validates"})
    if has_native and not any(n["id"] == "native" for n in nodes):
        nodes.append({"id": "native", "label": "Native (.so) TLS / JNI", "kind": "native"})
        edges.append({"from": "app", "to": "native", "label": "System.loadLibrary"})
        edges.append({"from": "native", "to": "trust_anchor", "label": "OpenSSL/BoringSSL?"})
    return nodes, edges


def _trust_flow_mermaid(nodes: list[dict[str, str]], edges: list[dict[str, str]]) -> str:
    lines = ["flowchart LR"]
    for n in nodes:
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", n["id"])
        label = n["label"].replace('"', "'")
        lines.append(f'  {safe}["{label}"]')
    for e in edges:
        a = re.sub(r"[^a-zA-Z0-9_]", "_", e["from"])
        b = re.sub(r"[^a-zA-Z0-9_]", "_", e["to"])
        lab = (e.get("label") or "").replace('"', "'")
        if lab:
            lines.append(f"  {a} -->|{lab}| {b}")
        else:
            lines.append(f"  {a} --> {b}")
    return "\n".join(lines)


def _build_frida_script(hits: list[PinningHit], ranked: list[tuple[str, int]]) -> str:
    libs = {lid for lid, _ in ranked}
    blocks: list[str] = [
        "// Auto-generated by APPredator SSL Pinning Mapper — tune class names for your build.",
        "// Run: frida -U -f com.package.name -l ssl_pinning_bypass.js --no-pause",
        "",
        "Java.perform(function () {",
    ]

    if "okhttp" in libs:
        blocks.append(
            """
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
      console.log('[+] OkHttp CertificatePinner.check bypass for', hostname);
      return;
    };
  } catch (e) {
    console.log('[-] OkHttp CertificatePinner hook failed:', e);
  }
  try {
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (host, session) {
      console.log('[+] OkHostnameVerifier.verify bypass', host);
      return true;
    };
  } catch (e) {
    console.log('[-] OkHostnameVerifier hook failed:', e);
  }""".strip()
        )

    if "trustkit" in libs:
        blocks.append(
            """
  try {
    var TKPinner = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
    TKPinner.checkServerTrusted.implementation = function (chain, authType) {
      console.log('[+] TrustKit checkServerTrusted bypass');
      return;
    };
  } catch (e) {
    console.log('[-] TrustKit hook failed (class may differ by version):', e);
  }""".strip()
        )

    if "cronet" in libs:
        blocks.append(
            """
  try {
    var CronetEngine = Java.use('org.chromium.net.CronetEngine$Builder');
    CronetEngine.enablePublicKeyPinningBypassForLocalTrustStores.implementation = function () {
      console.log('[+] Cronet public key pinning bypass flag');
      return this;
    };
  } catch (e) {
    console.log('[-] Cronet hook failed:', e);
  }""".strip()
        )

    if "flutter" in libs:
        blocks.append(
            """
  // Flutter: often pinned in Dart — hook platform channels or rebuild HttpClient in Dart layer.
  console.log('[*] Flutter detected — consider reFlutter / custom Dart patches; Java hooks alone may be insufficient.');""".strip()
        )

    blocks.append(
        """
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      console.log('[+] Conscrypt TrustManagerImpl.verifyChain bypass for', host);
      return untrustedChain;
    };
  } catch (e) {
    console.log('[-] TrustManagerImpl hook failed:', e);
  }
});""".strip()
    )

    return "\n\n".join(blocks)
