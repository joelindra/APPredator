import { useCallback, useEffect, useMemo, useState } from "react";
import { apiGetJadxMaxHeap, apiPostSslPinningMapStream, apiPutJadxMaxHeap } from "../api";
import { IconCheck, IconDoc, IconFolder, IconTrash, IconX } from "./Icons";

export type TrustFlowNode = { id: string; label: string; kind: string };
export type TrustFlowEdge = { from: string; to: string; label?: string };

export type SslPinningMapResult = {
  apk_name?: string;
  libraries_detected?: { id: string; hits: number; label: string }[];
  locations?: {
    library: string;
    display_name: string;
    mechanism: string;
    file: string;
    language: string;
    line?: number | null;
    confidence: string;
    evidence: string;
  }[];
  language_summary?: Record<string, number>;
  native_libraries_sample?: string[];
  native_library_total?: number;
  native_smali_hints?: string[];
  trust_flow?: { nodes: TrustFlowNode[]; edges: TrustFlowEdge[] };
  trust_flow_mermaid?: string;
  frida_script?: string;
  notes?: string[];
  decompiled_summary?: { has_manifest: boolean; has_smali: boolean; has_java: boolean };
};

export type SslPinningProgress = { pct: number; stage: string; message: string };

type MapProgressStep = { stage: string; message: string; pct: number; at: number };

export type SslPinningJobRecord = {
  jobId: string;
  inputFileName: string;
  status: "running" | "success" | "error";
  progress: SslPinningProgress | null;
  steps: MapProgressStep[];
  result: SslPinningMapResult | null;
  errorMessage?: string;
};

const SSL_PIN_MAP_MAX_JOBS = 8;

/** Long-running stages: stream updates replace the last row instead of appending (one line, not many). */
const STAGES_MERGE_IN_PLACE = new Set(["apktool", "jadx", "scan"]);

function mergeStreamingStep(
  steps: MapProgressStep[],
  p: { stage: string; message: string; pct: number }
): MapProgressStep[] {
  const next: MapProgressStep = { stage: p.stage, message: p.message, pct: p.pct, at: Date.now() };
  const last = steps[steps.length - 1];
  if (last && STAGES_MERGE_IN_PLACE.has(p.stage) && last.stage === p.stage) {
    return [...steps.slice(0, -1), next];
  }
  return [...steps, next];
}

/** Preset -Xmx values for JADX (must match server `normalize_jadx_max_heap_arg` rules). */
const JADX_HEAP_PRESETS = ["2048m", "3072m", "4096m", "5120m", "6144m", "8192m", "10240m", "12288m", "16384m"] as const;

function jadxHeapSelectOptions(currentSaved: string): { value: string; label: string }[] {
  const rows: { value: string; label: string }[] = [{ value: "", label: "Default (env / YAML / 4096m)" }];
  for (const v of JADX_HEAP_PRESETS) {
    rows.push({ value: v, label: v });
  }
  const t = currentSaved.trim();
  if (t && !rows.some((r) => r.value === t)) {
    rows.push({ value: t, label: `${t} (saved)` });
  }
  return rows;
}

type Props = {
  isBusy: (k: string) => boolean;
  run: (k: string, fn: () => Promise<void>) => void;
  setErr: (msg: string | null) => void;
  onSuccessToast?: (message: string) => void;
};

function confidenceBadgeClass(raw: string): string {
  const c = (raw || "").toLowerCase().trim();
  if (c === "critical") return "ssl-pin-conf ssl-pin-conf--critical";
  if (c === "high") return "ssl-pin-conf ssl-pin-conf--high";
  if (c === "medium") return "ssl-pin-conf ssl-pin-conf--medium";
  if (c === "low") return "ssl-pin-conf ssl-pin-conf--low";
  if (c === "info") return "ssl-pin-conf ssl-pin-conf--info";
  return "ssl-pin-conf ssl-pin-conf--unknown";
}

function formatElapsed(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m > 0 ? `${m}:${s.toString().padStart(2, "0")}` : `${s}s`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeDownloadStem(name: string): string {
  const base = name.replace(/\.(apk|xapk)$/i, "");
  const t = base.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
  return (t || "ssl-pinning-map").slice(0, 96);
}

function buildSslPinningMapHtml(job: SslPinningJobRecord): string {
  const title = "SSL Pinning Map — Report";
  const when = new Date().toISOString();
  const css = `body{font-family:system-ui,sans-serif;margin:1.5rem;background:#0f1419;color:#e6edf3}
h1{font-size:1.25rem}h2{font-size:1rem;margin-top:1.25rem}
.muted{color:#8b949e;font-size:0.9rem}
.card{border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1rem;background:#161b22}
table{border-collapse:collapse;width:100%;font-size:0.82rem}
th,td{border:1px solid #30363d;padding:0.45rem 0.5rem;text-align:left;vertical-align:top}
th{background:#21262d}
pre{white-space:pre-wrap;word-break:break-word;font-size:0.78rem;background:#0d1117;padding:0.75rem;border-radius:6px;overflow-x:auto}
.badge{display:inline-block;padding:0.12rem 0.45rem;border-radius:4px;font-size:0.75rem;background:#23863633;border:1px solid #3fb95055}
.err{color:#f85149}.ok{color:#3fb950}
ul.hint{margin:0;padding-left:1.2rem;color:#8b949e;font-size:0.88rem}
.step{border-left:3px solid #388bfd;padding-left:0.65rem;margin:0.35rem 0}
.step-meta{font-size:0.75rem;color:#8b949e;margin-bottom:0.15rem}`;

  const stepsHtml =
    job.steps.length > 0
      ? `<div class="card"><h2>Pipeline progress</h2>${job.steps
          .map(
            (s) =>
              `<div class="step"><div class="step-meta"><strong>${escapeHtml(s.stage)}</strong> · ${s.pct}% · ${new Date(
                s.at
              ).toISOString()}</div><div>${escapeHtml(s.message)}</div></div>`
          )
          .join("")}</div>`
      : "";

  let body = "";
  if (job.status === "error" && job.errorMessage) {
    body += `<div class="card"><h2>Error</h2><pre class="err">${escapeHtml(job.errorMessage)}</pre></div>`;
  }
  const r = job.result;
  if (r) {
    const libs = (r.libraries_detected || [])
      .map((lib) => `<li><strong>${escapeHtml(lib.label)}</strong> <span class="muted">(${escapeHtml(lib.id)})</span> — ${lib.hits} hit(s)</li>`)
      .join("");
    body += `<div class="card"><h2>Libraries detected</h2>${libs ? `<ul>${libs}</ul>` : "<p class=\"muted\">No known pinning stacks matched.</p>"}`;
    if (r.decompiled_summary) {
      body += `<p class="muted mono">manifest=${r.decompiled_summary.has_manifest} · smali=${r.decompiled_summary.has_smali} · java_sources=${r.decompiled_summary.has_java}</p>`;
    }
    body += `</div>`;

    const locs = (r.locations || []).slice(0, 500);
    const locRows = locs
      .map(
        (loc) =>
          `<tr><td>${escapeHtml(loc.display_name)}</td><td>${escapeHtml(loc.mechanism)}</td><td class="mono">${escapeHtml(
            loc.file
          )}</td><td>${escapeHtml(loc.language)}</td><td>${escapeHtml(loc.confidence)}</td></tr>`
      )
      .join("");
    body += `<div class="card"><h2>Pinning locations (${locs.length})</h2><table><thead><tr><th>Library</th><th>Mechanism</th><th>File</th><th>Lang</th><th>Conf.</th></tr></thead><tbody>${locRows}</tbody></table></div>`;

    const lang = Object.entries(r.language_summary || {})
      .map(([k, n]) => `<tr><td>${escapeHtml(k)}</td><td>${n}</td></tr>`)
      .join("");
    if (lang) body += `<div class="card"><h2>Language summary</h2><table><tbody>${lang}</tbody></table></div>`;

    if (r.native_library_total) {
      body += `<div class="card"><h2>Native libraries (${r.native_library_total} .so)</h2><pre>${escapeHtml(
        (r.native_libraries_sample || []).join("\n")
      )}</pre></div>`;
    }

    if (r.trust_flow?.nodes?.length) {
      const nodes = [...r.trust_flow.nodes]
        .sort((a, b) => {
          const rank = (id: string) => (id === "app" ? 0 : id === "trust_anchor" ? 2 : 1);
          const d = rank(a.id) - rank(b.id);
          return d !== 0 ? d : a.label.localeCompare(b.label);
        })
        .map((n) => `${escapeHtml(n.label)} <span class="muted mono">(${escapeHtml(n.id)})</span>`)
        .join(" → ");
      body += `<div class="card"><h2>Trust flow</h2><p>${nodes}</p>`;
      if (r.trust_flow_mermaid) body += `<h3 class="muted">Mermaid</h3><pre>${escapeHtml(r.trust_flow_mermaid)}</pre>`;
      body += `</div>`;
    } else if (r.trust_flow_mermaid) {
      body += `<div class="card"><h2>Trust flow (Mermaid)</h2><pre>${escapeHtml(r.trust_flow_mermaid)}</pre></div>`;
    }

    if (r.frida_script) {
      body += `<div class="card"><h2>Frida script (starter)</h2><pre>${escapeHtml(r.frida_script)}</pre></div>`;
    }

    if ((r.notes || []).length) {
      body += `<div class="card"><h2>Notes</h2><ul class="hint">${(r.notes || []).map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul></div>`;
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${escapeHtml(title)}</title>
<style>${css}</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
<p class="muted">Package: <strong class="mono">${escapeHtml(job.inputFileName)}</strong> · Generated <span class="mono">${escapeHtml(
    when
  )}</span></p>
${stepsHtml}
${body}
<p class="muted">For authorized security testing only. Verify all findings manually.</p>
</body>
</html>`;
}

function downloadHtml(filename: string, html: string) {
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function TrustFlowViz({ flow }: { flow: { nodes: TrustFlowNode[]; edges: TrustFlowEdge[] } }) {
  const nodes = [...(flow.nodes || [])].sort((a, b) => {
    const rank = (id: string) => (id === "app" ? 0 : id === "trust_anchor" ? 2 : 1);
    const d = rank(a.id) - rank(b.id);
    return d !== 0 ? d : a.label.localeCompare(b.label);
  });
  return (
    <div className="trust-flow-viz" aria-label="Trust flow diagram">
      {nodes.map((n, i) => (
        <div key={n.id} className="trust-flow-viz__row">
          {i > 0 && <span className="trust-flow-viz__arrow" aria-hidden />}
          <div className={`trust-flow-viz__node trust-flow-viz__node--${n.kind}`}>
            <span className="trust-flow-viz__node-label">{n.label}</span>
            <span className="trust-flow-viz__node-id mono">{n.id}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function renderMapResultContent(result: SslPinningMapResult, copyFrida: () => void, copyMermaid: () => void) {
  return (
    <>
      <div className="card" style={{ marginTop: "1rem" }}>
        <h3>Libraries detected</h3>
        {(result.libraries_detected || []).length === 0 ? (
          <p className="hint">No known pinning stacks matched. Check native binaries or custom obfuscation.</p>
        ) : (
          <ul className="ssl-pin-lib-list">
            {(result.libraries_detected || []).map((lib) => (
              <li key={lib.id}>
                <strong>{lib.label}</strong> <span className="mono hint">({lib.id})</span>
                <span className="badge badge-neutral" style={{ marginLeft: "0.35rem" }}>
                  {lib.hits} hit{lib.hits === 1 ? "" : "s"}
                </span>
              </li>
            ))}
          </ul>
        )}
        {result.decompiled_summary && (
          <p className="mono hint" style={{ marginTop: "0.5rem" }}>
            Decompile: manifest={String(result.decompiled_summary.has_manifest)} · smali={String(result.decompiled_summary.has_smali)} ·
            java_sources={String(result.decompiled_summary.has_java)}
          </p>
        )}
      </div>

      <div className="card" style={{ marginTop: "1rem" }}>
        <h3>Pinning locations</h3>
        <div className="live-table-wrap">
          <table className="live-findings-table">
            <thead>
              <tr>
                <th>Library</th>
                <th>Mechanism</th>
                <th>File</th>
                <th>Lang</th>
                <th>Conf.</th>
              </tr>
            </thead>
            <tbody>
              {(result.locations || []).slice(0, 200).map((loc, idx) => (
                <tr key={`${loc.file}-${idx}`}>
                  <td>{loc.display_name}</td>
                  <td style={{ color: "var(--text-secondary)", fontSize: "0.85rem" }}>{loc.mechanism}</td>
                  <td className="mono" style={{ maxWidth: "14rem", overflow: "hidden", textOverflow: "ellipsis" }} title={loc.file}>
                    {loc.file}
                  </td>
                  <td>
                    <span className="badge badge-info">{loc.language}</span>
                  </td>
                  <td>
                    <span className={confidenceBadgeClass(loc.confidence)} title={loc.confidence}>
                      {loc.confidence}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: "1rem" }}>
        <h3>Language &amp; stack (Java / Kotlin / Smali / native)</h3>
        <div className="stat-grid" style={{ marginTop: "0.5rem" }}>
          {Object.entries(result.language_summary || {}).map(([lang, n]) => (
            <div key={lang} className="stat-card">
              <div className="stat-card__label">{lang}</div>
              <div className="stat-card__value">{n}</div>
            </div>
          ))}
        </div>
        {!!result.native_library_total && (
          <div style={{ marginTop: "0.75rem" }}>
            <h4 className="hint" style={{ margin: "0 0 0.35rem" }}>
              Native libraries ({result.native_library_total} .so)
            </h4>
            <pre className="mono log-panel" style={{ maxHeight: "140px", fontSize: "0.75rem" }}>
              {(result.native_libraries_sample || []).join("\n")}
            </pre>
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: "1rem" }}>
        <h3>Trust flow (visual)</h3>
        {result.trust_flow && <TrustFlowViz flow={result.trust_flow} />}
        <h4 style={{ marginTop: "1rem", fontSize: "0.9rem" }}>Mermaid (paste into mermaid.live)</h4>
        <pre className="mono log-panel" style={{ maxHeight: "160px", fontSize: "0.78rem" }}>
          {result.trust_flow_mermaid || ""}
        </pre>
        <button type="button" className="btn-sm btn-ghost" style={{ marginTop: "0.35rem" }} onClick={() => void copyMermaid()}>
          Copy Mermaid
        </button>
      </div>

      <div className="card" style={{ marginTop: "1rem" }}>
        <h3>Frida script (starter)</h3>
        <button type="button" className="btn-sm btn-primary" style={{ marginBottom: "0.5rem" }} onClick={() => void copyFrida()}>
          Copy script
        </button>
        <pre className="mono log-panel" style={{ maxHeight: "320px", fontSize: "0.75rem" }}>
          {result.frida_script || ""}
        </pre>
      </div>

      {(result.notes || []).length > 0 && (
        <div className="card" style={{ marginTop: "1rem" }}>
          <h3>Notes</h3>
          <ul className="hint" style={{ margin: 0, paddingLeft: "1.2rem" }}>
            {(result.notes || []).map((n) => (
              <li key={n} style={{ marginBottom: "0.25rem" }}>
                {n}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

export function SslPinningMapperPanel({ isBusy, run, setErr, onSuccessToast }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [inputKey, setInputKey] = useState(0);
  const [jobs, setJobs] = useState<SslPinningJobRecord[]>([]);
  const [detailsJobId, setDetailsJobId] = useState<string | null>(null);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [jadxMaxHeap, setJadxMaxHeap] = useState("");

  const busy = isBusy("sslPinning");
  const busyJadxSave = isBusy("sslPinJadxHeap");

  const jadxHeapOptions = useMemo(() => jadxHeapSelectOptions(jadxMaxHeap), [jadxMaxHeap]);

  useEffect(() => {
    let cancelled = false;
    void apiGetJadxMaxHeap()
      .then((r) => {
        if (!cancelled) setJadxMaxHeap((r.max_heap ?? "").trim());
      })
      .catch(() => {
        /* settings optional at cold start */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!busy) {
      setElapsedSec(0);
      return;
    }
    const t0 = Date.now();
    const id = window.setInterval(() => setElapsedSec(Math.floor((Date.now() - t0) / 1000)), 400);
    return () => clearInterval(id);
  }, [busy]);

  useEffect(() => {
    if (!detailsJobId) return;
    if (!jobs.some((j) => j.jobId === detailsJobId)) setDetailsJobId(null);
  }, [jobs, detailsJobId]);

  const analyze = useCallback(() => {
    if (!file) return;
    const jobId = `map-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    void run("sslPinning", async () => {
      setErr(null);
      const t0 = Date.now();
      setJobs((prev) => {
        const row: SslPinningJobRecord = {
          jobId,
          inputFileName: file.name,
          status: "running",
          progress: { pct: 0, stage: "starting", message: "Uploading package and opening progress stream…" },
          steps: [{ stage: "starting", message: "Uploading package and opening progress stream…", pct: 0, at: t0 }],
          result: null,
        };
        return [row, ...prev].slice(0, SSL_PIN_MAP_MAX_JOBS);
      });
      setDetailsJobId(null);
      try {
        const res = (await apiPostSslPinningMapStream(
          file,
          (p) => {
            setJobs((prev) =>
              prev.map((j) =>
                j.jobId === jobId
                  ? {
                      ...j,
                      progress: p,
                      steps: mergeStreamingStep(j.steps, p),
                    }
                  : j
              )
            );
          },
          jadxMaxHeap.trim() || null
        )) as SslPinningMapResult;
        setJobs((prev) =>
          prev.map((j) =>
            j.jobId === jobId
              ? {
                  ...j,
                  status: "success",
                  progress: { pct: 100, stage: "done", message: "Done." },
                  result: res,
                }
              : j
          )
        );
        onSuccessToast?.("SSL pinning map completed successfully.");
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setJobs((prev) =>
          prev.map((j) => (j.jobId === jobId ? { ...j, status: "error", progress: null, errorMessage: msg } : j))
        );
        throw e;
      }
    });
  }, [file, jadxMaxHeap, run, setErr, onSuccessToast]);

  const saveJadxHeapDefault = useCallback(() => {
    void run("sslPinJadxHeap", async () => {
      setErr(null);
      await apiPutJadxMaxHeap(jadxMaxHeap.trim());
      onSuccessToast?.("Default heap JADX disimpan (jadx.max_heap di settings).");
    });
  }, [jadxMaxHeap, run, setErr, onSuccessToast]);

  const copyFridaForJob = (result: SslPinningMapResult) => {
    if (!result?.frida_script) return;
    void navigator.clipboard.writeText(result.frida_script);
  };

  const copyMermaidForJob = (result: SslPinningMapResult) => {
    if (!result?.trust_flow_mermaid) return;
    void navigator.clipboard.writeText(result.trust_flow_mermaid);
  };

  const exportJobHtml = (job: SslPinningJobRecord) => {
    const html = buildSslPinningMapHtml(job);
    const stem = safeDownloadStem(job.inputFileName);
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    downloadHtml(`${stem}-ssl-pin-map-${stamp}.html`, html);
    onSuccessToast?.("HTML export started (check your downloads folder).");
  };

  const toggleDetails = (id: string) => {
    setDetailsJobId((cur) => (cur === id ? null : id));
  };

  const dismissJob = (id: string) => {
    setDetailsJobId((cur) => (cur === id ? null : cur));
    setJobs((prev) => prev.filter((j) => j.jobId !== id));
  };

  /** Badge class uses server stage ids (save, apktool, …); avoid invalid class from odd stage strings */
  const stageBadgeClass = (stage: string) => {
    const s = (stage || "save").toLowerCase().replace(/[^a-z0-9_-]/g, "");
    return `ssl-pinning-stage-badge ssl-pinning-stage-badge--${s || "save"}`;
  };

  const renderProgressStepsFixed = (job: SslPinningJobRecord) => {
    const steps = job.steps;
    const running = job.status === "running";
    return (
      <ul className="ssl-bypass-steps ssl-pin-map-progress-steps" aria-label="Pipeline progress">
        {steps.map((s, i) => {
          const isLast = i === steps.length - 1;
          const active = running && isLast;
          return (
            <li key={`${job.jobId}-step-${i}`} className="ssl-bypass-step">
              <span className={`ssl-bypass-step__icon${active ? " ssl-bypass-step__icon--active" : ""}`}>
                {active ? <span className="spinner" aria-hidden /> : <IconCheck size={18} />}
              </span>
              <div className="ssl-bypass-step__body">
                <div className="ssl-bypass-step__label" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.35rem" }}>
                  <span className={stageBadgeClass(s.stage)}>{s.stage}</span>
                  <span className="mono hint">{s.pct}%</span>
                </div>
                {s.message ? <div className="ssl-bypass-step__detail">{s.message}</div> : null}
              </div>
            </li>
          );
        })}
      </ul>
    );
  };

  const detailsJob = detailsJobId ? jobs.find((j) => j.jobId === detailsJobId) : null;

  const renderJobDetailsPanel = (job: SslPinningJobRecord) => (
    <div className="ssl-bypass-details ssl-pin-map-details" style={{ marginTop: "0.75rem" }}>
      <h4 className="ssl-bypass-result__sub">Pipeline progress</h4>
      {renderProgressStepsFixed(job)}

      {job.status === "error" && job.errorMessage && (
        <>
          <h4 className="ssl-bypass-result__sub" style={{ marginTop: "1rem" }}>
            Error
          </h4>
          <p className="mono" style={{ marginTop: 0, wordBreak: "break-word", whiteSpace: "pre-wrap" }}>
            {job.errorMessage}
          </p>
        </>
      )}

      {job.status === "success" && job.result && (
        <>
          <p className="ssl-bypass-details__summary-hint hint" style={{ marginTop: "1rem" }}>
            Full mapper output for <span className="mono">{job.inputFileName}</span>. Use <strong>Export to HTML</strong> for a standalone file
            (includes progress + findings).
          </p>
          {renderMapResultContent(job.result, () => copyFridaForJob(job.result!), () => copyMermaidForJob(job.result!))}
        </>
      )}
    </div>
  );

  return (
    <div className="ssl-pinning-page">
      <div className="card">
        <h3>Upload APK / XAPK</h3>
        <p className="hint" style={{ marginTop: 0 }}>
          Decompiles with Apktool and JADX (if configured), then scans for OkHttp CertificatePinner, TrustKit, Cronet, Flutter embeddings,
          Network Security Config pin-sets, and related TLS hooks. Progress streams from the server; each run appears in <strong>Map activity</strong>{" "}
          below (same pattern as Bypass SSL pinning).
        </p>

        <div
          className="ssl-pin-map-heap"
          style={{
            marginTop: "0.85rem",
            paddingTop: "0.85rem",
            borderTop: "1px solid var(--border-subtle, rgba(255,255,255,0.08))",
          }}
        >
          <h4 style={{ margin: "0 0 0.35rem", fontSize: "0.95rem" }}>JADX memory (-Xmx)</h4>
          <p className="hint" style={{ marginTop: 0, fontSize: "0.82rem", lineHeight: 1.45 }}>
            The <strong className="mono">jadx</strong> stage (~48%) decompiles Java across all DEX files; large APKs or very large method counts can take{" "}
            <strong>several minutes</strong> without the percentage moving until JADX finishes — that is expected. A larger heap helps avoid{" "}
            <span className="mono">OutOfMemoryError</span> but does not make the CPU finish proportionally faster. <strong>Pick -Xmx</strong> from the list for this run;{" "}
            <em>Default</em> follows the server chain: environment <span className="mono">APPREDATOR_JADX_MAX_HEAP</span>, then{" "}
            <span className="mono">jadx.max_heap</span> in YAML, then built-in default <span className="mono">4096m</span>. If{" "}
            <span className="mono">APPREDATOR_JADX_JAVA_OPTS</span> is set on the server, this dropdown is ignored.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.65rem", alignItems: "center", marginTop: "0.55rem" }}>
            <label htmlFor="ssl-pin-jadx-heap" style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.88rem", flexWrap: "wrap" }}>
              <span className="mono">-Xmx</span>
              <select
                id="ssl-pin-jadx-heap"
                className="mono"
                value={jadxMaxHeap}
                disabled={busy || busyJadxSave}
                onChange={(e) => setJadxMaxHeap(e.target.value)}
                style={{
                  minWidth: "9rem",
                  maxWidth: "100%",
                  padding: "0.35rem 0.5rem",
                  borderRadius: 6,
                  border: "1px solid var(--border-input)",
                  background: "var(--bg-input)",
                  color: "var(--text-primary)",
                }}
                aria-label="JADX max heap (-Xmx)"
              >
                {jadxHeapOptions.map((o) => (
                  <option key={o.value || "__default"} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="btn-ghost btn-sm"
              disabled={busy || busyJadxSave}
              onClick={() => void saveJadxHeapDefault()}
            >
              {busyJadxSave ? "Saving…" : "Save as default"}
            </button>
          </div>
        </div>

        <label htmlFor="ssl-pin-apk-input" className="file-drop file-drop--scan" style={{ marginTop: "1rem", display: "block" }}>
          <input
            key={inputKey}
            id="ssl-pin-apk-input"
            type="file"
            accept=".apk,.xapk"
            className="file-drop__native-input"
            disabled={busy}
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
            }}
          />
          <div className="file-drop__scan-inner">
            <div className="file-drop__scan-copy">
              <span className="file-drop__scan-title">Select application package</span>
              <span className="file-drop__scan-sub hint">Analysis runs on the server (temporary decompile, then deleted).</span>
            </div>
            <div className="file-drop__scan-actions">
              <span className="file-drop__scan-btn">Choose file…</span>
              <span className="file-drop__scan-formats mono">.apk · .xapk</span>
            </div>
          </div>
        </label>
        {file && (
          <p className="file-drop__selected mono hint">
            Selected: <strong className="file-drop__selected-name">{file.name}</strong>
          </p>
        )}
        <div className="btn-row" style={{ marginTop: "0.85rem" }}>
          <button type="button" className="btn-primary" disabled={!file || busy} onClick={() => void analyze()}>
            {busy ? "Running…" : "Run SSL pinning map"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={!file || busy}
            onClick={() => {
              setFile(null);
              setInputKey((k) => k + 1);
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {jobs.length > 0 && (
        <section
          className="ssl-bypass-persist ssl-pin-map-activity"
          aria-label="SSL pinning map jobs"
          style={{ marginTop: "1.25rem" }}
        >
          <div className="card">
            <p className="ssl-bypass-fm__caption">Map activity</p>
            <p className="hint" style={{ marginTop: 0, marginBottom: "0.65rem", fontSize: "0.8rem" }}>
              Each row is one map run. Open <strong>Details</strong> for the full report and progress list. <strong>Export to HTML</strong> saves
              pipeline steps plus findings (up to {SSL_PIN_MAP_MAX_JOBS} runs kept — dismiss old rows to trim).
            </p>
            <div className="ssl-bypass-fm ssl-bypass-fm--job ssl-bypass-fm--job-multi">
              <div className="ssl-bypass-fm__head">
                <span>Package</span>
                <span>Status</span>
                <span>Progress</span>
                <span className="ssl-bypass-fm__actions" style={{ justifyContent: "flex-start" }}>
                  Actions
                </span>
              </div>
              {jobs.map((job) => {
                const pct = job.progress?.pct ?? (job.status === "success" ? 100 : 0);
                return (
                  <div key={job.jobId} className="ssl-bypass-fm__row">
                    <div className="ssl-bypass-fm__name">
                      <IconFolder size={16} aria-hidden />
                      <span className="ssl-bypass-fm__name-text mono" title={job.inputFileName}>
                        {job.inputFileName}
                      </span>
                    </div>
                    <div>
                      {job.status === "running" && (
                        <span className="ssl-bypass-fm__status ssl-bypass-fm__status--run">
                          {job.progress?.stage ? String(job.progress.stage).toUpperCase() : "RUNNING"}
                        </span>
                      )}
                      {job.status === "success" && <span className="ssl-bypass-fm__status ssl-bypass-fm__status--ok">Done</span>}
                      {job.status === "error" && <span className="ssl-bypass-fm__status ssl-bypass-fm__status--err">Failed</span>}
                    </div>
                    <div className="ssl-bypass-fm__progress">
                      {job.status === "running" && (
                        <>
                          <span className="ssl-bypass-fm__pct mono">
                            {pct}% · {formatElapsed(elapsedSec)}
                          </span>
                          <div className="ssl-bypass-fm__bar" aria-hidden>
                            <div className="ssl-bypass-fm__bar-fill" style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
                          </div>
                        </>
                      )}
                      {job.status === "success" && (
                        <>
                          <span className="ssl-bypass-fm__pct mono">100%</span>
                          <div className="ssl-bypass-fm__bar" aria-hidden>
                            <div className="ssl-bypass-fm__bar-fill" style={{ width: "100%" }} />
                          </div>
                        </>
                      )}
                      {job.status === "error" && <span className="ssl-bypass-fm__pct mono">—</span>}
                    </div>
                    <div className="ssl-bypass-fm__actions">
                      {job.status === "running" && (
                        <span className="hint" style={{ fontSize: "0.78rem" }}>
                          Expand <strong>Details</strong> after completion
                        </span>
                      )}
                      {(job.status === "success" || job.status === "error") && (
                        <>
                          <button type="button" className="btn-ghost btn-sm" aria-expanded={detailsJobId === job.jobId} onClick={() => toggleDetails(job.jobId)}>
                            <IconDoc aria-hidden /> {detailsJobId === job.jobId ? "Hide details" : "Details"}
                          </button>
                          {(job.status === "success" && job.result) || job.status === "error" ? (
                            <button type="button" className="btn-primary btn-sm" onClick={() => exportJobHtml(job)}>
                              Export to HTML
                            </button>
                          ) : null}
                          <button type="button" className="btn-ghost btn-sm" onClick={() => dismissJob(job.jobId)}>
                            <IconTrash aria-hidden /> Dismiss
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {jobs.some((j) => j.status === "running") && (
              <div style={{ marginTop: "0.75rem" }}>
                <h4 className="ssl-bypass-result__sub">Live progress</h4>
                <p className="hint" style={{ marginTop: 0, marginBottom: "0.5rem", fontSize: "0.8rem" }}>
                  {jobs.find((j) => j.status === "running")?.progress?.message ?? "Starting…"}
                </p>
                {(() => {
                  const run = jobs.find((j) => j.status === "running");
                  return run ? renderProgressStepsFixed(run) : null;
                })()}
              </div>
            )}

            {jobs.map((job) => {
              if (job.status !== "success" || detailsJobId === job.jobId || !job.result) return null;
              return (
                <p key={`hint-${job.jobId}`} className="hint" style={{ marginTop: "0.45rem", marginBottom: 0, fontSize: "0.8rem" }}>
                  <IconCheck size={14} style={{ verticalAlign: "text-bottom", marginRight: "0.25rem" }} aria-hidden />
                  <span className="mono">{job.inputFileName}</span> — open <strong>Details</strong> for libraries, locations, Frida starter, and Mermaid.
                </p>
              );
            })}

            {jobs.map((job) => {
              if (job.status !== "error" || detailsJobId === job.jobId || !job.errorMessage) return null;
              return (
                <p key={`err-hint-${job.jobId}`} className="hint" style={{ marginTop: "0.45rem", marginBottom: 0, fontSize: "0.8rem" }}>
                  <IconX size={14} style={{ verticalAlign: "text-bottom", marginRight: "0.25rem", color: "var(--danger)" }} aria-hidden />
                  <span className="mono">{job.inputFileName}</span> — open <strong>Details</strong> for the full error and progress log.
                </p>
              );
            })}

            {detailsJob && (detailsJob.status === "success" || detailsJob.status === "error") && renderJobDetailsPanel(detailsJob)}
          </div>
        </section>
      )}
    </div>
  );
}
