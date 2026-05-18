/** Home landing dashboard. */
import type { ReactNode } from "react";
import {
  IconBot,
  IconCog,
  IconHeart,
  IconList,
  IconLock,
  IconRadar,
  IconRefresh,
  IconSearch,
  IconShield,
  IconUnlock,
  IconUpload,
} from "./Icons";

/** Subset of main app tabs reachable from the home dashboard. */
export type HomeNavigateTarget =
  | "scan"
  | "scanning"
  | "config"
  | "prompts"
  | "rules"
  | "health"
  | "wizard"
  | "jobs"
  | "baseline"
  | "ssl-pinning"
  | "ssl-bypass";

type HealthLite = {
  status?: string;
  llm_provider?: string;
  settings_path?: string;
  java?: { ok: boolean };
  apktool?: { ok: boolean };
  jadx?: { ok: boolean };
  ubersigner?: { ok: boolean };
};

type Props = {
  onNavigate: (target: HomeNavigateTarget) => void;
  health: HealthLite | null;
  /** From deep health when available; null = not loaded yet */
  settingsFileExists: boolean | null;
  jobsCount: number;
  onRefreshHealth: () => void | Promise<void>;
  healthBusy: boolean;
};

function StatusDot({ ok }: { ok: boolean | undefined }) {
  if (ok === undefined) return <span className="home-dash__dot home-dash__dot--muted" title="Unknown" />;
  return (
    <span
      className={`home-dash__dot${ok ? " home-dash__dot--ok" : " home-dash__dot--bad"}`}
      title={ok ? "OK" : "Issue"}
    />
  );
}

function BentoCard({
  title,
  desc,
  icon,
  className,
  onClick,
  badge,
}: {
  title: string;
  desc: string;
  icon: ReactNode;
  className?: string;
  onClick: () => void;
  badge?: string;
}) {
  return (
    <button type="button" className={`home-dash__bento-card${className ? ` ${className}` : ""}`} onClick={onClick}>
      <span className="home-dash__bento-icon" aria-hidden>
        {icon}
      </span>
      {badge && <span className="home-dash__bento-badge">{badge}</span>}
      <span className="home-dash__bento-title">{title}</span>
      <span className="home-dash__bento-desc">{desc}</span>
    </button>
  );
}

export function HomeDashboard({ onNavigate, health, settingsFileExists, jobsCount, onRefreshHealth, healthBusy }: Props) {
  const toolsOk = health?.java?.ok && health?.apktool?.ok && health?.jadx?.ok && health?.ubersigner?.ok;
  const settingsOk = settingsFileExists !== false;
  const activitySub =
    jobsCount === 0 ? "No active scan jobs" : jobsCount === 1 ? "1 job in history" : `${jobsCount} jobs in history`;

  return (
    <div className="home-dash">
      <header className="home-dash__hero">
        <div className="home-dash__hero-bg" aria-hidden />
        <div className="home-dash__hero-shine" aria-hidden />
        <div className="home-dash__hero-inner">
          <p className="home-dash__eyebrow">Android security workspace</p>
          <h1 className="home-dash__title">
            Welcome to <span className="home-dash__title-accent">APPredator</span>
          </h1>
          <p className="home-dash__lead">
            Static analysis, LLM-assisted review, and hardening workflows in one console. Upload an APK, tune your RAG
            prompts, and track findings from scan to report.
          </p>
          <div className="home-dash__hero-actions">
            <button type="button" className="home-dash__btn home-dash__btn--primary" onClick={() => onNavigate("scan")}>
              <IconSearch size={16} aria-hidden /> New scan
            </button>
            <button type="button" className="home-dash__btn home-dash__btn--outline" onClick={() => onNavigate("scanning")}>
              <IconRadar size={16} aria-hidden /> Live dashboard
            </button>
          </div>
        </div>
      </header>

      <div className="home-dash__body">
        <section className="home-dash__status-bar" aria-label="Environment status">
          <div className="home-dash__status-card">
            <div className="home-dash__status-head">
              <span className="home-dash__status-label">Toolchain</span>
              <button
                type="button"
                className="home-dash__refresh"
                disabled={healthBusy}
                onClick={() => void onRefreshHealth()}
                title="Refresh status"
              >
                <IconRefresh size={14} aria-hidden /> {healthBusy ? "…" : "Refresh"}
              </button>
            </div>
            <ul className="home-dash__status-list">
              <li>
                <StatusDot ok={health?.java?.ok} /> Java
              </li>
              <li>
                <StatusDot ok={health?.apktool?.ok} /> Apktool
              </li>
              <li>
                <StatusDot ok={health?.jadx?.ok} /> JADX
              </li>
              <li>
                <StatusDot ok={health?.ubersigner?.ok} /> UberSigner
              </li>
            </ul>
            {toolsOk === false && (
              <p className="home-dash__status-hint">
                Open <strong>Getting Started</strong> or <strong>System Health</strong> to fix paths.
              </p>
            )}
          </div>
          <div className="home-dash__status-card">
            <span className="home-dash__status-label">Configuration</span>
            <p className="home-dash__status-mono">{health?.llm_provider ? String(health.llm_provider) : "—"}</p>
            <p className="home-dash__status-sublabel">LLM provider</p>
            <p
              className={`home-dash__pill${
                settingsFileExists === null ? " home-dash__pill--neutral" : settingsOk ? " home-dash__pill--ok" : " home-dash__pill--warn"
              }`}
            >
              {settingsFileExists === null ? "Loading…" : settingsOk ? "Settings file found" : "Settings file missing"}
            </p>
            {health?.settings_path && (
              <p className="home-dash__status-path mono" title={health.settings_path}>
                {health.settings_path}
              </p>
            )}
          </div>
          <div className="home-dash__status-card">
            <span className="home-dash__status-label">Activity</span>
            <p className="home-dash__stat-num">{jobsCount}</p>
            <p className="home-dash__status-sublabel">{activitySub}</p>
            <button type="button" className="home-dash__status-link" onClick={() => onNavigate("jobs")}>
              View history
            </button>
          </div>
        </section>

        <section className="home-dash__bento" aria-labelledby="home-bento-heading">
          <h2 id="home-bento-heading" className="home-dash__section-title">
            Quick access
          </h2>
          <div className="home-dash__bento-grid">
            <BentoCard
              className="home-dash__bento-card--wide"
              title="New scan"
              desc="Upload an APK or XAPK and queue static + LLM analysis."
              icon={<IconSearch size={22} />}
              onClick={() => onNavigate("scan")}
              badge="Analysis"
            />
            <BentoCard
              title="Live dashboard"
              desc="Stream logs, severity charts, and partial findings."
              icon={<IconRadar size={22} />}
              onClick={() => onNavigate("scanning")}
            />
            <BentoCard
              title="RAG & prompts"
              desc="Edit retrieval context and rule templates."
              icon={<IconBot size={22} />}
              onClick={() => onNavigate("prompts")}
            />
            <BentoCard
              title="AI configuration"
              desc="Provider, model, and analysis defaults."
              icon={<IconCog size={22} />}
              onClick={() => onNavigate("config")}
            />
            <BentoCard
              title="Detection rules"
              desc="Toggle static checks used during scans."
              icon={<IconList size={22} />}
              onClick={() => onNavigate("rules")}
            />
            <BentoCard
              title="Getting started"
              desc="Tool paths and deep health checks."
              icon={<IconUpload size={22} />}
              onClick={() => onNavigate("wizard")}
            />
            <BentoCard
              title="System health"
              desc="Java, decompilers, signer, and LLM probe."
              icon={<IconHeart size={22} />}
              onClick={() => onNavigate("health")}
            />
            <BentoCard
              title="Baselines"
              desc="Suppress known-good fingerprints."
              icon={<IconShield size={22} />}
              onClick={() => onNavigate("baseline")}
            />
            <BentoCard
              title="SSL pinning map"
              desc="Static map of pinning stacks and Frida starters."
              icon={<IconLock size={22} />}
              onClick={() => onNavigate("ssl-pinning")}
            />
            <BentoCard
              title="SSL bypass & repack"
              desc="NSC + smali stubs, rebuild, re-sign."
              icon={<IconUnlock size={22} />}
              onClick={() => onNavigate("ssl-bypass")}
            />
          </div>
        </section>
      </div>

      <footer className="home-dash__foot">
        <span className="home-dash__foot-brand">
          <IconLock size={14} aria-hidden /> APPredator Security Console
        </span>
        <span className="home-dash__foot-meta">
          <span className="home-dash__foot-spark" aria-hidden>
            ✦
          </span>{" "}
          Authorized testing only — use on apps you own or are permitted to assess.
        </span>
      </footer>
    </div>
  );
}
