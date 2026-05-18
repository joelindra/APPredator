import type { LiveSummary } from "./types";

const COLORS = ["#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#ea580c", "#4f46e5"];

function arc(cx: number, cy: number, r: number, start: number, end: number) {
  const x1 = cx + r * Math.cos(start);
  const y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end);
  const y2 = cy + r * Math.sin(end);
  const large = end - start > Math.PI ? 1 : 0;
  return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
}

export function CategoryDonutChart({ summary }: { summary: LiveSummary | null }) {
  const all = Object.entries(summary?.category_counts ?? {}).sort((a, b) => b[1] - a[1]);
  const top = all.slice(0, 6);
  const total = top.reduce((n, [, v]) => n + Number(v || 0), 0);
  const radius = 46;
  const center = 60;
  let acc = -Math.PI / 2;
  return (
    <div className="chart-card">
      <h4>Top Vulnerability Categories</h4>
      {total > 0 ? (
        <div className="donut-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120" className="donut-svg">
            <circle cx={center} cy={center} r={radius} fill="none" stroke="#e5e7eb" strokeWidth="14" />
            {top.map(([name, value], i) => {
              const frac = Number(value || 0) / total;
              const start = acc;
              const end = acc + frac * Math.PI * 2;
              acc = end;
              return <path key={name} d={arc(center, center, radius, start, end)} stroke={COLORS[i % COLORS.length]} strokeWidth="14" fill="none" />;
            })}
            <text x="60" y="56" textAnchor="middle" className="donut-center-num">
              {total}
            </text>
            <text x="60" y="72" textAnchor="middle" className="donut-center-label">
              findings
            </text>
          </svg>
          <div className="legend-list">
            {top.map(([name, value], i) => (
              <div key={name} className="legend-item">
                <span className="legend-dot" style={{ background: COLORS[i % COLORS.length] }} />
                <span className="legend-name">{name}</span>
                <span className="legend-val">{value}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-chart">No findings yet.</div>
      )}
    </div>
  );
}
