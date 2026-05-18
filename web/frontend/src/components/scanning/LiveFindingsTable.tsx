import { useMemo, useState } from "react";
import type { LiveFinding } from "./types";

type SortKey = "ts" | "severity" | "triage" | "vulnerability" | "file";

function sevRank(s: string): number {
  const m: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 };
  return m[(s || "").toLowerCase()] ?? 0;
}

function triageRank(s: string): number {
  const m: Record<string, number> = { critical_now: 3, review: 2, info: 1 };
  return m[(s || "").toLowerCase()] ?? 0;
}

export function LiveFindingsTable({ items }: { items: LiveFinding[] }) {
  const [sort, setSort] = useState<SortKey>("ts");
  const [onlyVuln, setOnlyVuln] = useState(true);
  const sorted = useMemo(() => {
    const base = onlyVuln ? items.filter((x) => x.status === "Vulnerable") : items.slice();
    base.sort((a, b) => {
      if (sort === "severity") return sevRank(b.severity) - sevRank(a.severity);
      if (sort === "triage") return triageRank(b.triage_level || "") - triageRank(a.triage_level || "");
      if (sort === "vulnerability") return a.vulnerability.localeCompare(b.vulnerability);
      if (sort === "file") return a.file.localeCompare(b.file);
      return String(b.ts).localeCompare(String(a.ts));
    });
    return base.slice(0, 500);
  }, [items, sort, onlyVuln]);

  return (
    <div className="live-table-card">
      <div className="live-table-toolbar">
        <h4>
          Live Findings{" "}
          <span className="badge badge-neutral" style={{ marginLeft: "0.4rem" }}>
            {sorted.length}
          </span>
        </h4>
        <div className="live-table-actions">
          <label className="inline-check">
            <input type="checkbox" checked={onlyVuln} onChange={(e) => setOnlyVuln(e.target.checked)} />
            Vulnerable only
          </label>
          <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)} style={{ minWidth: "9rem" }}>
            <option value="ts">Sort: Newest</option>
            <option value="severity">Sort: Severity</option>
            <option value="triage">Sort: Triage</option>
            <option value="vulnerability">Sort: Category</option>
            <option value="file">Sort: File</option>
          </select>
        </div>
      </div>
      {sorted.length === 0 ? (
        <div className="empty-chart" style={{ minHeight: "120px" }}>
          {items.length === 0
            ? "Waiting for findings… they will appear here as they are discovered."
            : "No vulnerable findings yet. Toggle off “Vulnerable only” to see all findings."}
        </div>
      ) : (
        <div className="live-table-wrap">
          <table className="live-findings-table">
            <thead>
              <tr>
                <th style={{ width: "94px" }}>Triage</th>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>File</th>
                <th>Description</th>
                <th style={{ width: "92px" }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f) => (
                <tr key={f.id}>
                  <td>
                    <span className="badge badge-neutral">{f.triage_level || "info"}</span>
                  </td>
                  <td>
                    <span className={`sev-chip sev-${(f.severity || "unknown").toLowerCase()}`}>{f.severity || "unknown"}</span>
                  </td>
                  <td style={{ color: "var(--text-primary)", fontWeight: 500 }}>{f.vulnerability}</td>
                  <td className="mono" style={{ color: "var(--text-secondary)", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.file}>
                    {f.file}
                  </td>
                  <td style={{ color: "var(--text-secondary)" }} title={f.triage_reason || f.remediation_summary}>
                    {f.description || f.evidence || "—"}
                    {f.remediation_summary ? <div style={{ fontSize: "0.75rem", marginTop: "0.2rem" }}>{f.remediation_summary}</div> : null}
                    {f.owasp_mobile_top10 ? <div className="mono" style={{ fontSize: "0.7rem", marginTop: "0.2rem" }}>{f.owasp_mobile_top10}</div> : null}
                  </td>
                  <td className="mono" style={{ color: "var(--text-muted)" }}>{f.ts ? new Date(f.ts).toLocaleTimeString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
