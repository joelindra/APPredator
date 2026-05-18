/** Inline “checking” animation: spinner + optional label + pulsing dots */

export function CheckSpinner({ label = "Checking" }: { label?: string }) {
  return (
    <div className="check-spinner" role="status" aria-live="polite">
      <span className="spinner" aria-hidden />
      <span className="check-label">{label}</span>
      <span className="check-dots" aria-hidden>
        <span>.</span>
        <span>.</span>
        <span>.</span>
      </span>
    </div>
  );
}

export function BusyOverlay({ show, text }: { show: boolean; text: string }) {
  if (!show) return null;
  return (
    <div className="busy-overlay" role="status">
      <div className="busy-card">
        <span className="spinner" />
        <span>{text}</span>
      </div>
    </div>
  );
}
