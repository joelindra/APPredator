const jsonHeaders: HeadersInit = {
  "Content-Type": "application/json",
};

export async function apiGet(path: string): Promise<unknown> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export async function apiPut(path: string, body: unknown): Promise<unknown> {
  const r = await fetch(path, {
    method: "PUT",
    headers: jsonHeaders,
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export async function apiPost(path: string, body: unknown): Promise<unknown> {
  const r = await fetch(path, {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export async function apiDelete(path: string): Promise<unknown> {
  const r = await fetch(path, { method: "DELETE" });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export async function apiPostScan(file: File, options: Record<string, unknown>): Promise<{ job_id: string }> {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("options", JSON.stringify(options));
  const r = await fetch("/api/scans", { method: "POST", body: fd });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json() as Promise<{ job_id: string }>;
}

export async function apiGetLiveFindings(jobId: string): Promise<unknown> {
  const r = await fetch(`/api/scans/${encodeURIComponent(jobId)}/findings-live`);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export type SslPinningStreamEvent =
  | { type: "progress"; pct: number; stage: string; message: string }
  | { type: "complete"; result: unknown }
  | { type: "error"; message: string };

export async function apiGetJadxMaxHeap(): Promise<{ max_heap: string }> {
  return apiGet("/api/config/jadx-max-heap") as Promise<{ max_heap: string }>;
}

export async function apiPutJadxMaxHeap(max_heap: string): Promise<{ max_heap: string }> {
  return apiPut("/api/config/jadx-max-heap", { max_heap }) as Promise<{ max_heap: string }>;
}

/**
 * Streams NDJSON from POST /api/ssl-pinning/map-stream (stage-based progress, then result).
 * Optional jadxMaxHeap (e.g. 4096m, 8g) sets JVM -Xmx for this run when sent non-empty.
 */
export async function apiPostSslPinningMapStream(
  file: File,
  onProgress: (p: { pct: number; stage: string; message: string }) => void,
  jadxMaxHeap?: string | null
): Promise<unknown> {
  const fd = new FormData();
  fd.append("file", file);
  const h = (jadxMaxHeap ?? "").trim();
  if (h) fd.append("jadx_max_heap", h);
  const r = await fetch("/api/ssl-pinning/map-stream", { method: "POST", body: fd });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  const reader = r.body?.getReader();
  if (!reader) throw new Error("No response body");
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      const out = handleLine(t);
      if (out !== undefined) return out;
    }
  }
  const tail = buf.trim();
  if (tail) {
    const out = handleLine(tail);
    if (out !== undefined) return out;
  }
  throw new Error("Stream ended without a result");

  function handleLine(t: string): unknown | undefined {
    let ev: SslPinningStreamEvent;
    try {
      ev = JSON.parse(t) as SslPinningStreamEvent;
    } catch {
      throw new Error("Invalid stream line from server");
    }
    if (ev.type === "progress") onProgress({ pct: ev.pct, stage: ev.stage, message: ev.message });
    if (ev.type === "error") throw new Error(ev.message);
    if (ev.type === "complete") return ev.result;
    return undefined;
  }
}

/** Non-streaming fallback (no progress events). */
export async function apiPostSslPinningMap(file: File): Promise<unknown> {
  const fd = new FormData();
  fd.append("file", file);
  const r = await fetch("/api/ssl-pinning/map", { method: "POST", body: fd });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export async function apiPostSslBypassPreview(file: File, options: Record<string, boolean>): Promise<unknown> {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("options", JSON.stringify(options));
  const r = await fetch("/api/ssl-bypass/preview", { method: "POST", body: fd });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

export type SslBypassBuildStep = { key: string; label: string; ok: boolean; detail?: string };

export type PinningBypassNscSummary = {
  enabled?: boolean;
  outcome?: string;
  headline?: string;
  mode?: string;
  had_pinning?: boolean;
};

export type PinningBypassSmaliSurfaceRow = {
  rule_id: string;
  title: string;
  option_key: string;
  option_enabled: boolean;
  mapper_location_hits: number;
  patched_files: number;
  patch_edits: number;
  patched: boolean;
  status: string;
  /** Present when status is armed_mapper_only — explains why no Smali edit landed. */
  status_hint?: string | null;
};

export type PinningBypassSummary = {
  network_security?: PinningBypassNscSummary;
  smali_surfaces?: PinningBypassSmaliSurfaceRow[];
  coverage_note?: string;
};

export type SslBypassBuildReport = {
  steps?: SslBypassBuildStep[];
  download_filename?: string;
  input_apk?: string;
  libraries_detected?: { id: string; hits: number; label: string }[];
  location_count?: number;
  locations_preview?: unknown[];
  nsc?: Record<string, unknown>;
  smali_journal?: { rule: string; file: string; edits?: number; note?: string }[];
  smali_journal_total?: number;
  smali_logs?: string[];
  signer_internal_filename?: string;
  options?: Record<string, boolean>;
  pinning_bypass_summary?: PinningBypassSummary;
};

export type SslBypassRunStreamEvent =
  | { type: "progress"; pct: number; stage: string; message: string }
  | { type: "complete"; download_token: string; report?: SslBypassBuildReport }
  | { type: "error"; message: string };

export async function apiPostSslBypassRunStream(
  file: File,
  options: Record<string, boolean>,
  onProgress: (p: { pct: number; stage: string; message: string }) => void
): Promise<{ download_token: string; report?: SslBypassBuildReport }> {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("options", JSON.stringify(options));
  const res = await fetch("/api/ssl-bypass/run-stream", { method: "POST", body: fd });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  const reader = res.body?.getReader();
  if (!reader) throw new Error("No response body");
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      const out = handleLine(t);
      if (out) return out;
    }
  }
  const tail = buf.trim();
  if (tail) {
    const out = handleLine(tail);
    if (out) return out;
  }
  throw new Error("Stream ended without a complete event");

  function handleLine(t: string): { download_token: string; report?: SslBypassBuildReport } | undefined {
    let ev: SslBypassRunStreamEvent;
    try {
      ev = JSON.parse(t) as SslBypassRunStreamEvent;
    } catch {
      throw new Error("Invalid stream line from server");
    }
    if (ev.type === "progress") onProgress({ pct: ev.pct, stage: ev.stage, message: ev.message });
    if (ev.type === "error") throw new Error(ev.message);
    if (ev.type === "complete") return { download_token: ev.download_token, report: ev.report };
    return undefined;
  }
}

export function sslBypassDownloadUrl(token: string): string {
  return `/api/ssl-bypass/download/${encodeURIComponent(token)}`;
}

/** Fetch signed APK bytes (same session as token); server deletes artifact after response. */
export async function apiDownloadSslBypassBlob(token: string): Promise<Blob> {
  const r = await fetch(sslBypassDownloadUrl(token));
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.blob();
}
