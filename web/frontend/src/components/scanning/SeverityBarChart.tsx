import type { LiveSummary } from "./types";

const ORDER = ["critical", "high", "medium", "low", "info", "unknown"] as const;

export function SeverityBarChart({ summary }: { summary: LiveSummary | null }) {
  const counts = summary?.severity_counts ?? {};
  const data = ORDER.map((k) => ({ key: k, value: Number(counts[k] || 0) }));
  const max = Math.max(1, ...data.map((x) => x.value));
  return (
    <div className="chart-card">
      <h4>Severity Breakdown</h4>
      <div className="bar-list">
        {data.map((d) => (
          <div key={d.key} className="bar-row">
            <span className={`sev-chip sev-${d.key}`}>{d.key}</span>
            <div className="bar-track">
              <div className={`bar-fill sev-${d.key}`} style={{ width: `${(d.value / max) * 100}%` }} />
            </div>
            <span className="bar-value">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
