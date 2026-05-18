import type { TimelinePoint } from "./types";

export function FindingsTimelineChart({ points }: { points: TimelinePoint[] }) {
  const data = points.slice(-80);
  const max = Math.max(1, ...data.map((x) => Number(x.vulnerable_count || 0)));
  const w = 520;
  const h = 130;
  const pad = 12;
  const path = data
    .map((p, i) => {
      const x = pad + (i / Math.max(1, data.length - 1)) * (w - pad * 2);
      const y = h - pad - (Number(p.vulnerable_count || 0) / max) * (h - pad * 2);
      return `${i === 0 ? "M" : "L"} ${x} ${y}`;
    })
    .join(" ");
  return (
    <div className="chart-card">
      <h4>Vulnerabilities Over Time</h4>
      {data.length > 1 ? (
        <svg viewBox={`0 0 ${w} ${h}`} className="timeline-svg" aria-label="vulnerability timeline">
          <line x1={pad} y1={h - pad} x2={w - pad} y2={h - pad} stroke="#e5e7eb" />
          <line x1={pad} y1={pad} x2={pad} y2={h - pad} stroke="#e5e7eb" />
          <path d={path} fill="none" stroke="#2563eb" strokeWidth="2.4" />
        </svg>
      ) : (
        <div className="empty-chart">Collecting timeline data…</div>
      )}
    </div>
  );
}
