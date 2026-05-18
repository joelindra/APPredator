import type { ReactNode } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiDelete, apiGet, apiGetLiveFindings, apiPost, apiPostScan, apiPut } from "./api";
import { BusyOverlay, CheckSpinner } from "./components/CheckSpinner";
import {
  IconAlert,
  IconBot,
  IconCog,
  IconDoc,
  IconDownload,
  IconFolder,
  IconHeart,
  IconHome,
  IconList,
  IconLock,
  IconUnlock,
  IconPlay,
  IconRadar,
  IconRefresh,
  IconSearch,
  IconShield,
  IconTrash,
  IconUpload,
} from "./components/Icons";
import { HomeDashboard } from "./components/HomeDashboard";
import { PromptsWorkspace } from "./components/PromptsWorkspace";
import { SslPinningMapperPanel } from "./components/SslPinningMapperPanel";
import { CategoryDonutChart } from "./components/scanning/CategoryDonutChart";
import { FindingsTimelineChart } from "./components/scanning/FindingsTimelineChart";
import { LiveFindingsTable } from "./components/scanning/LiveFindingsTable";
import { SeverityBarChart } from "./components/scanning/SeverityBarChart";
import type { LiveFinding, LiveSummary, TimelinePoint } from "./components/scanning/types";

type Tab =
  | "home"
  | "wizard"
  | "health"
  | "settings"
  | "config"
  | "prompts"
  | "rules"
  | "scan"
  | "scanning"
  | "jobs"
  | "baseline"
  | "ssl-pinning"
  | "ssl-bypass";

type HealthPayload = {
  status?: string;
  java?: { ok: boolean; output?: string };
  apktool?: { ok: boolean; output?: string };
  jadx?: { ok: boolean; output?: string };
  ubersigner?: { ok: boolean; output?: string };
  llm_provider?: string;
  settings_path?: string;
  settings_file_exists?: boolean;
};

type JobRow = {
  id: string;
  status: string;
  apk_path?: string;
  report_json_path?: string;
  error?: string;
  created_at?: string;
  updated_at?: string;
  meta?: { filename?: string; findings_summary?: unknown };
};

type RuleRow = { id: string; enabled: boolean; description: string };

type LiveFindingsPayload = {
  job_id: string;
  status?: string;
  last_partial_at?: string;
  summary?: LiveSummary;
  findings?: LiveFinding[];
  timeline_points?: TimelinePoint[];
};

type LlmCredentialResponse = {
  provider?: string | null;
  kind: "none" | "url" | "api_key";
  label?: string | null;
  value?: string | null;
  configured: boolean;
  credential_yaml_key?: string | null;
  model_yaml_key?: string | null;
  yaml_hint?: string | null;
  /** Non-secret: character count of key on disk */
  secret_length?: number;
  /** Masked preview (bullets + last 4 chars) so UI shows sync with settings.yaml */
  secret_preview?: string | null;
  settings_path?: string | null;
};

/**
 * Matches `config/settings.yaml` under `llm:` and `web/backend/routers/config_parity.py` `_LLM_YAML_LAYOUT`.
 * Gemini uses `llm.api_key` (not gemini_api_key).
 */
const LLM_PROVIDER_OPTIONS: { id: string; label: string; modelPlaceholder: string; keyHint: string }[] = [
  {
    id: "ollama",
    label: "Ollama (local)",
    modelPlaceholder: "llama3:8b",
    keyHint: "YAML: llm.model + llm.ollama_url — no API key; matches config/settings.yaml.",
  },
  {
    id: "gemini",
    label: "Google Gemini",
    modelPlaceholder: "gemini-2.0-flash",
    keyHint: "YAML: llm.api_key (Gemini) + llm.gemini_model — same names as in settings.yaml.",
  },
  {
    id: "groq",
    label: "Groq",
    modelPlaceholder: "llama-3.1-8b-instant",
    keyHint: "YAML: llm.groq_api_key + llm.groq_model — Groq model id (not Ollama-style names).",
  },
  {
    id: "openai",
    label: "OpenAI",
    modelPlaceholder: "gpt-4-turbo",
    keyHint: "YAML: llm.openai_api_key + llm.openai_model.",
  },
  {
    id: "anthropic",
    label: "Anthropic",
    modelPlaceholder: "claude-sonnet-4-20250514",
    keyHint: "YAML: llm.anthropic_api_key + llm.anthropic_model.",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    modelPlaceholder: "google/gemini-2.5-flash",
    keyHint: "YAML: llm.openrouter_api_key + llm.openrouter_model.",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    modelPlaceholder: "deepseek-v4-pro",
    keyHint:
      "YAML: llm.deepseek_api_key + llm.deepseek_model; optional llm.deepseek_base_url, deepseek_reasoning_effort, deepseek_thinking_enabled (see comments in settings.yaml). Env DEEPSEEK_API_KEY is also read if the YAML key is empty.",
  },
];

function llmModelPlaceholder(provider: string): string {
  return LLM_PROVIDER_OPTIONS.find((o) => o.id === provider)?.modelPlaceholder ?? "model id";
}

function llmKeyHint(provider: string): string {
  return (
    LLM_PROVIDER_OPTIONS.find((o) => o.id === provider)?.keyHint ??
    "Unknown provider: edit llm block manually in Settings JSON or settings.yaml."
  );
}

/** Chromium/Electron exposes `File.path`; standard browsers do not (paste path manually). */
function tryFileAbsolutePath(file: File): string | null {
  const p = (file as File & { path?: string }).path;
  if (typeof p === "string" && p.trim()) {
    return p.trim();
  }
  return null;
}

function useBusy(setErr: (msg: string | null) => void) {
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const isBusy = (k: string) => !!busy[k];
  const run = useCallback(
    async (k: string, fn: () => Promise<void>) => {
      setBusy((s) => ({ ...s, [k]: true }));
      try {
        await fn();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy((s) => ({ ...s, [k]: false }));
      }
    },
    [setErr]
  );
  return { isBusy, run };
}

function ToolTile({ title, data }: { title: string; data?: { ok: boolean; output?: string } }) {
  const ok = data?.ok === true;
  return (
    <div className="health-tile">
      <h3>{title}</h3>
      <div className={ok ? "status-ok" : "status-bad"}>
        <span className={`badge ${ok ? "badge-ok" : "badge-danger"}`}>{ok ? "Healthy" : "Unavailable"}</span>
      </div>
      {data?.output && <pre className="mono health-tile-output">{data.output}</pre>}
    </div>
  );
}

function PageHeader({ title, desc, actions, breadcrumb }: { title: string; desc?: string; actions?: ReactNode; breadcrumb?: string[] }) {
  return (
    <>
      {breadcrumb && breadcrumb.length > 0 && (
        <nav className="breadcrumb" aria-label="Breadcrumb">
          <ol>
            {breadcrumb.map((segment, i) => (
              <li key={`${segment}-${i}`}>
                {i > 0 && <span className="breadcrumb-sep" aria-hidden>/</span>}
                <span>{segment}</span>
              </li>
            ))}
          </ol>
        </nav>
      )}
      <header className="page-header">
        <div style={{ minWidth: 0, flex: "1 1 14rem" }}>
          <h1 className="page-title">{title}</h1>
          {desc && <p className="page-desc">{desc}</p>}
        </div>
        {actions && <div className="btn-row">{actions}</div>}
      </header>
    </>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("home");
  const [err, setErr] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [healthDeep, setHealthDeep] = useState<HealthPayload | null>(null);
  const [settingsText, setSettingsText] = useState("");
  const [validateResult, setValidateResult] = useState<unknown>(null);
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [baselines, setBaselines] = useState<{
    entries: { id: string; fingerprint: string; application_id: string; reason: string; created_at?: string }[];
  } | null>(null);
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [scanVerbose, setScanVerbose] = useState(false);
  const [scanNoDecompile, setScanNoDecompile] = useState(false);
  const [scanGenExploit, setScanGenExploit] = useState(false);
  const [scanLibs, setScanLibs] = useState(false);
  const [scanProfile, setScanProfile] = useState("");
  const [scanOutput, setScanOutput] = useState("");
  const [scanRulesRaw, setScanRulesRaw] = useState("");
  const [scanOverridesJson, setScanOverridesJson] = useState("null");
  const [lastJob, setLastJob] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [wsBusy, setWsBusy] = useState(false);
  const [scanningJobId, setScanningJobId] = useState("");
  const [scanJobDetail, setScanJobDetail] = useState<Record<string, unknown> | null>(null);
  const [scanningLogs, setScanningLogs] = useState<string[]>([]);
  const [liveFindings, setLiveFindings] = useState<LiveFinding[]>([]);
  const [liveSummary, setLiveSummary] = useState<LiveSummary | null>(null);
  const [liveTimeline, setLiveTimeline] = useState<TimelinePoint[]>([]);
  const [scanningWsBusy, setScanningWsBusy] = useState(false);
  const [scanningAutoScroll, setScanningAutoScroll] = useState(true);
  const scanningLogPreRef = useRef<HTMLPreElement>(null);
  const [scanPendingFile, setScanPendingFile] = useState<File | null>(null);
  const [scanFileInputKey, setScanFileInputKey] = useState(0);

  const [cfgProvider, setCfgProvider] = useState("ollama");
  const [cfgModel, setCfgModel] = useState("");
  /** Preset model ids from GET /api/config/llm-model-options (per provider). */
  const [llmModelPresets, setLlmModelPresets] = useState<{ value: string; label: string }[]>([]);
  const [filterMode, setFilterMode] = useState("hybrid");
  const [decompilerMode, setDecompilerMode] = useState("hybrid");
  const [attackSurface, setAttackSurface] = useState(false);
  const [contextInjection, setContextInjection] = useState(true);
  const [generateExploit, setGenerateExploit] = useState(false);
  const [scanLibraries, setScanLibraries] = useState(false);
  const [dsBaseUrl, setDsBaseUrl] = useState("");
  const [dsReasoning, setDsReasoning] = useState("");
  const [dsThinking, setDsThinking] = useState<"unset" | "on" | "off">("unset");
  const [serverTuning, setServerTuning] = useState<{ items?: { name: string; description: string; configured: boolean }[] } | null>(null);
  const [profiles, setProfiles] = useState<string[]>([]);
  const [profileNewName, setProfileNewName] = useState("");
  const [profileCopyFrom, setProfileCopyFrom] = useState("");
  const [profileSwitch, setProfileSwitch] = useState("");
  const [wizardApktoolPath, setWizardApktoolPath] = useState("");
  const [wizardJadxPath, setWizardJadxPath] = useState("");
  const [wizardUbersignerPath, setWizardUbersignerPath] = useState("");
  const wizardApktoolBrowseRef = useRef<HTMLInputElement>(null);
  const wizardJadxBrowseRef = useRef<HTMLInputElement>(null);
  const wizardUbersignerBrowseRef = useRef<HTMLInputElement>(null);
  const scanApkDragNest = useRef(0);
  const [scanApkDragActive, setScanApkDragActive] = useState(false);

  const [cfgCredKind, setCfgCredKind] = useState<LlmCredentialResponse["kind"]>("none");
  const [cfgCredLabel, setCfgCredLabel] = useState("");
  const [cfgCredConfigured, setCfgCredConfigured] = useState(false);
  const [cfgCredValue, setCfgCredValue] = useState("");
  const [cfgClearApiKey, setCfgClearApiKey] = useState(false);
  const [cfgYamlCredKey, setCfgYamlCredKey] = useState("");
  const [cfgYamlModelKey, setCfgYamlModelKey] = useState("");
  const [cfgSecretLength, setCfgSecretLength] = useState(0);
  const [cfgSecretPreview, setCfgSecretPreview] = useState("");
  const [cfgSettingsPath, setCfgSettingsPath] = useState("");
  type LlmTestResult = {
    ok: boolean;
    provider?: string;
    message?: string;
    latency_ms?: number | null;
    endpoint?: string;
    model?: string;
  };
  const [llmTestResult, setLlmTestResult] = useState<LlmTestResult | null>(null);
  const [appToast, setAppToast] = useState<string | null>(null);
  const appToastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { isBusy, run } = useBusy(setErr);

  const showAppToast = useCallback((message: string) => {
    if (appToastTimerRef.current) {
      clearTimeout(appToastTimerRef.current);
      appToastTimerRef.current = null;
    }
    setAppToast(message);
    appToastTimerRef.current = setTimeout(() => {
      setAppToast(null);
      appToastTimerRef.current = null;
    }, 8000);
  }, []);

  useEffect(() => {
    if (err) {
      setAppToast(null);
      if (appToastTimerRef.current) {
        clearTimeout(appToastTimerRef.current);
        appToastTimerRef.current = null;
      }
    }
  }, [err]);

  const loadHealth = useCallback(async () => {
    setErr(null);
    const h = (await apiGet("/api/health")) as HealthPayload;
    setHealth(h);
  }, []);

  const loadHealthDeep = useCallback(async () => {
    setErr(null);
    const h = (await apiGet("/api/health/deep")) as HealthPayload;
    setHealthDeep(h);
  }, []);

  const loadSettings = useCallback(async () => {
    setErr(null);
    const s = (await apiGet("/api/settings")) as { data: unknown };
    setSettingsText(JSON.stringify(s.data, null, 2));
  }, []);

  const loadValidate = useCallback(async () => {
    setErr(null);
    setValidateResult(await apiGet("/api/settings/validate"));
  }, []);

  const loadJobs = useCallback(async () => {
    setErr(null);
    const j = (await apiGet("/api/scans")) as { jobs: JobRow[] };
    setJobs(j.jobs || []);
  }, []);

  const loadBaselines = useCallback(async () => {
    setErr(null);
    setBaselines((await apiGet("/api/baselines")) as typeof baselines);
  }, []);

  const loadRules = useCallback(async () => {
    setErr(null);
    const r = (await apiGet("/api/rules")) as { rules: RuleRow[] };
    setRules(r.rules || []);
  }, []);

  const loadWizardToolPaths = useCallback(async () => {
    setErr(null);
    const [a, j, u] = await Promise.all([
      apiGet("/api/config/apktool-path") as Promise<{ path?: string }>,
      apiGet("/api/config/jadx-path") as Promise<{ path?: string }>,
      apiGet("/api/config/ubersigner-jar-path") as Promise<{ path?: string }>,
    ]);
    setWizardApktoolPath(a.path ?? "");
    setWizardJadxPath(j.path ?? "");
    setWizardUbersignerPath(u.path ?? "");
  }, []);

  const saveWizardToolPaths = async () => {
    await run("wizardSavePaths", async () => {
      setErr(null);
      await apiPut("/api/config/apktool-path", { path: wizardApktoolPath });
      await apiPut("/api/config/jadx-path", { path: wizardJadxPath });
      await apiPut("/api/config/ubersigner-jar-path", { path: wizardUbersignerPath });
    });
  };

  const setRuleEnabled = (id: string, enable: boolean) => {
    void run("ruleToggle", async () => {
      setErr(null);
      await apiPost("/api/config/rules", { rules: [id], enable });
      await loadRules();
    });
  };

  const applyLlmCredentialResponse = useCallback((cred: LlmCredentialResponse) => {
    const k = cred.kind === "url" || cred.kind === "api_key" ? cred.kind : "none";
    setCfgCredKind(k);
    setCfgCredLabel(cred.label ?? "");
    setCfgCredConfigured(!!cred.configured);
    setCfgClearApiKey(false);
    if (k === "none") {
      setCfgYamlCredKey("");
      setCfgYamlModelKey("");
      setCfgCredValue("");
      setCfgSecretLength(0);
      setCfgSecretPreview("");
      setCfgSettingsPath("");
      return;
    }
    setCfgSettingsPath(cred.settings_path ?? "");
    setCfgYamlCredKey(cred.credential_yaml_key ?? "");
    setCfgYamlModelKey(cred.model_yaml_key ?? "");
    setCfgSecretLength(typeof cred.secret_length === "number" ? cred.secret_length : 0);
    setCfgSecretPreview(cred.secret_preview ?? "");
    if (cred.kind === "url") {
      setCfgCredValue(String(cred.value ?? ""));
    } else {
      setCfgCredValue("");
    }
  }, []);

  const refreshLlmModelAndCredential = useCallback(
    async (p: string) => {
      setErr(null);
      const [mod, cred, catalog] = await Promise.all([
        apiGet(`/api/config/model?provider=${encodeURIComponent(p)}`) as Promise<{ model?: string }>,
        apiGet(`/api/config/llm-credential?provider=${encodeURIComponent(p)}`) as Promise<LlmCredentialResponse>,
        apiGet(`/api/config/llm-model-options?provider=${encodeURIComponent(p)}`) as Promise<{ options?: { value: string; label: string }[] }>,
      ]);
      setCfgModel(mod.model ?? "");
      applyLlmCredentialResponse(cred);
      setLlmModelPresets(Array.isArray(catalog.options) ? catalog.options : []);
    },
    [setErr, applyLlmCredentialResponse]
  );

  const loadConfigForm = useCallback(async () => {
    setErr(null);
    const prov = (await apiGet("/api/config/provider")) as { provider?: string };
    const p = (prov.provider || "").trim() || "ollama";
    const [mod, fm, dm, atk, ctx, ge, sl, profs, cred, dsAdv, cat] = await Promise.all([
      apiGet(`/api/config/model?provider=${encodeURIComponent(p)}`) as Promise<{ model?: string }>,
      apiGet("/api/config/filter-mode") as Promise<{ filter_mode: string }>,
      apiGet("/api/config/decompiler-mode") as Promise<{ decompiler_mode: string }>,
      apiGet("/api/config/attack-surface") as Promise<{ generate_attack_surface_map: boolean }>,
      apiGet("/api/config/context-injection") as Promise<{ use_cross_reference_context: boolean }>,
      apiGet("/api/config/generate-exploit") as Promise<{ generate_exploit: boolean }>,
      apiGet("/api/config/scan-libraries") as Promise<{ scan_libraries: boolean }>,
      apiGet("/api/config/profiles") as Promise<{ profiles: string[] }>,
      apiGet(`/api/config/llm-credential?provider=${encodeURIComponent(p)}`) as Promise<LlmCredentialResponse>,
      apiGet("/api/config/llm-deepseek-advanced") as Promise<{
        deepseek_base_url?: string | null;
        deepseek_reasoning_effort?: string | null;
        deepseek_thinking_enabled?: boolean | null;
      }>,
      apiGet(`/api/config/llm-model-options?provider=${encodeURIComponent(p)}`) as Promise<{ options?: { value: string; label: string }[] }>,
    ]);
    setCfgProvider(p);
    setCfgModel(mod.model ?? "");
    setLlmModelPresets(Array.isArray(cat.options) ? cat.options : []);
    applyLlmCredentialResponse(cred);
    setFilterMode(fm.filter_mode);
    setDecompilerMode(dm.decompiler_mode);
    setAttackSurface(!!atk.generate_attack_surface_map);
    setContextInjection(!!ctx.use_cross_reference_context);
    setGenerateExploit(!!ge.generate_exploit);
    setScanLibraries(!!sl.scan_libraries);
    setProfiles(profs.profiles || []);
    setDsBaseUrl((dsAdv.deepseek_base_url as string) || "");
    setDsReasoning((dsAdv.deepseek_reasoning_effort as string) || "");
    const te = dsAdv.deepseek_thinking_enabled;
    if (te === true) setDsThinking("on");
    else if (te === false) setDsThinking("off");
    else setDsThinking("unset");
  }, [applyLlmCredentialResponse]);

  useEffect(() => {
    if (tab === "health") void run("health", loadHealth);
    if (tab === "settings") void run("settings", loadSettings);
    if (tab === "jobs") void run("jobs", loadJobs);
    if (tab === "baseline") void run("baseline", loadBaselines);
    if (tab === "rules") void run("rules", loadRules);
    if (tab === "config") void run("configForm", loadConfigForm);
    if (tab === "home") {
      void run("homeBoot", async () => {
        await loadHealth();
        await loadHealthDeep();
        await loadJobs();
      });
    }
    if (tab === "wizard") void run("wizardPaths", loadWizardToolPaths);
    if (tab === "scanning") void run("scanningJobs", loadJobs);
    if (tab === "health") {
      void run("healthTuning", async () => {
        setServerTuning(
          (await apiGet("/api/health/server-tuning")) as {
            items?: { name: string; description: string; configured: boolean }[];
          }
        );
      });
    }
  }, [tab, run, loadHealth, loadHealthDeep, loadSettings, loadJobs, loadBaselines, loadRules, loadConfigForm, loadWizardToolPaths]);

  useEffect(() => {
    if (tab !== "scanning") return;
    if (!scanningJobId && lastJob) setScanningJobId(lastJob);
  }, [tab, lastJob, scanningJobId]);

  useEffect(() => {
    if (tab !== "scanning" || !scanningJobId) {
      if (tab !== "scanning") return;
      setScanJobDetail(null);
      setScanningLogs([]);
      setLiveFindings([]);
      setLiveSummary(null);
      setLiveTimeline([]);
      return;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        setErr(null);
        const [j, lg, live] = await Promise.all([
          apiGet(`/api/scans/${encodeURIComponent(scanningJobId)}`) as Record<string, unknown>,
          apiGet(`/api/scans/${encodeURIComponent(scanningJobId)}/logs`) as { lines?: string[] },
          apiGetLiveFindings(scanningJobId) as Promise<LiveFindingsPayload>,
        ]);
        if (cancelled) return;
        setScanJobDetail(j as Record<string, unknown>);
        setScanningLogs(Array.isArray(lg.lines) ? lg.lines : []);
        setLiveFindings(Array.isArray(live.findings) ? live.findings : []);
        setLiveSummary(live.summary ?? null);
        setLiveTimeline(Array.isArray(live.timeline_points) ? live.timeline_points : []);
      } catch (e) {
        if (!cancelled) setErr(e instanceof Error ? e.message : String(e));
      }
    };
    void tick();
    const id = setInterval(tick, 2000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [tab, scanningJobId]);

  useEffect(() => {
    if (!scanningAutoScroll || !scanningLogPreRef.current) return;
    scanningLogPreRef.current.scrollTop = scanningLogPreRef.current.scrollHeight;
  }, [scanningLogs, scanningAutoScroll]);

  const saveSettings = async () => {
    await run("settingsSave", async () => {
      setErr(null);
      const data = JSON.parse(settingsText);
      await apiPut("/api/settings", { data });
      setValidateResult(await apiGet("/api/settings/validate"));
    });
  };

  const formatSettingsJson = () => {
    try {
      const parsed = JSON.parse(settingsText);
      setSettingsText(JSON.stringify(parsed, null, 2));
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const startScan = async () => {
    if (!scanPendingFile) return;
    await run("scan", async () => {
      setErr(null);
      let settings_overrides: unknown = null;
      const oj = scanOverridesJson.trim();
      if (oj && oj !== "null") {
        try {
          settings_overrides = JSON.parse(oj);
        } catch {
          throw new Error("Invalid JSON in settings overrides — fix or set to null");
        }
      }
      let rules: string[] | null = null;
      const rr = scanRulesRaw.trim();
      if (rr) {
        try {
          const parsed = JSON.parse(rr);
          if (Array.isArray(parsed)) rules = parsed.map(String);
          else throw new Error("rules must be a JSON array of rule ids");
        } catch {
          throw new Error('Rules must be valid JSON array, e.g. ["sql_injection","webview_xss"]');
        }
      }
      const opts = {
        verbose: scanVerbose,
        no_decompile: scanNoDecompile,
        generate_exploit: scanGenExploit,
        scan_libraries: scanLibs,
        profile: scanProfile.trim() || null,
        output: scanOutput.trim() || null,
        rules,
        settings_overrides,
      };
      const res = (await apiPostScan(scanPendingFile, opts)) as { job_id: string };
      setLastJob(res.job_id);
      setScanningJobId(res.job_id);
      showAppToast("Scan started successfully. The job is queued — follow it on the Live Dashboard.");
      setTab("scanning");
      await loadJobs();
    });
  };

  const connectLogs = (jobId: string) => {
    setWsBusy(true);
    setLogs([]);
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/scans/${jobId}/logs`);
    const lines: string[] = [];
    ws.onmessage = (ev) => {
      lines.push(String(ev.data));
      setLogs([...lines]);
    };
    ws.onerror = () => {
      setErr("WebSocket error");
      setWsBusy(false);
    };
    ws.onclose = () => setWsBusy(false);
  };

  const connectScanningLogs = (jobId: string) => {
    setScanningWsBusy(true);
    setScanningLogs([]);
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/scans/${encodeURIComponent(jobId)}/logs`);
    const lines: string[] = [];
    ws.onmessage = (ev) => {
      lines.push(String(ev.data));
      setScanningLogs([...lines]);
    };
    ws.onerror = () => {
      setErr("WebSocket error (scanning)");
      setScanningWsBusy(false);
    };
    ws.onclose = () => setScanningWsBusy(false);
  };

  const testLlmConnection = async () => {
    await run("llmTest", async () => {
      setErr(null);
      setLlmTestResult(null);
      const r = (await apiPost("/api/config/llm-test", {})) as LlmTestResult;
      setLlmTestResult(r);
    });
  };

  const applyProviderModel = async () => {
    setErr(null);
    await run("configApply", async () => {
      const provTrim = cfgProvider.trim();
      if (provTrim) await apiPut("/api/config/provider", { provider: provTrim });
      if (cfgModel.trim()) await apiPut("/api/config/model", { model: cfgModel.trim() });
      if (provTrim && cfgCredKind === "url") {
        await apiPut("/api/config/llm-credential", {
          provider: provTrim,
          value: cfgCredValue.trim() || "http://localhost:11434",
        });
      }
      if (provTrim && cfgCredKind === "api_key") {
        if (cfgClearApiKey) {
          await apiPut("/api/config/llm-credential", { provider: provTrim, clear: true });
        } else if (cfgCredValue.trim()) {
          await apiPut("/api/config/llm-credential", { provider: provTrim, value: cfgCredValue.trim() });
        }
      }
      await apiPut("/api/config/filter-mode", { mode: filterMode });
      await apiPut("/api/config/decompiler-mode", { mode: decompilerMode });
      await apiPut("/api/config/attack-surface", { enable: attackSurface });
      await apiPut("/api/config/context-injection", { enable: contextInjection });
      await apiPut("/api/config/generate-exploit", { enable: generateExploit });
      await apiPut("/api/config/scan-libraries", { enable: scanLibraries });
      if (provTrim === "deepseek") {
        const body: Record<string, unknown> = {
          deepseek_base_url: dsBaseUrl.trim() || null,
          deepseek_reasoning_effort: dsReasoning.trim() || null,
        };
        if (dsThinking === "unset") body.deepseek_thinking_enabled = null;
        else body.deepseek_thinking_enabled = dsThinking === "on";
        await apiPut("/api/config/llm-deepseek-advanced", body);
      }
      await loadConfigForm();
    });
  };

  const createProfile = async () => {
    if (!profileNewName.trim()) return;
    setErr(null);
    await run("profileCreate", async () => {
      await apiPost("/api/config/profiles", {
        name: profileNewName.trim(),
        copy_from: profileCopyFrom.trim() || null,
      });
      setProfileNewName("");
      await loadConfigForm();
    });
  };

  const switchProfile = async () => {
    if (!profileSwitch) return;
    setErr(null);
    await run("profileSwitch", async () => {
      await apiPost(`/api/config/profiles/${encodeURIComponent(profileSwitch)}/switch`, {});
      await loadConfigForm();
      await loadSettings();
    });
  };

  const deleteProfile = async (name: string) => {
    if (!confirm(`Delete profile "${name}"?`)) return;
    setErr(null);
    await run("profileDel", async () => {
      await apiDelete(`/api/config/profiles/${encodeURIComponent(name)}`);
      await loadConfigForm();
    });
  };

  const addBaseline = async (fp: string, appId: string, reason: string) => {
    setErr(null);
    await run("baselineAdd", async () => {
      await apiPost("/api/baselines", { fingerprint: fp, application_id: appId, reason });
      await loadBaselines();
    });
  };

  const deleteJob = async (id: string) => {
    if (!confirm("Remove job metadata and uploaded APK for this job?")) return;
    setErr(null);
    await run("jobDel", async () => {
      await apiDelete(`/api/scans/${id}`);
      await loadJobs();
    });
  };

  const NAV_ITEMS: { key: Tab; icon: ReactNode; label: string; group: "SETUP" | "ANALYSIS" }[] = [
    { key: "home", icon: <IconHome />, label: "Home", group: "SETUP" },
    { key: "wizard", icon: <IconUpload />, label: "Getting Started", group: "SETUP" },
    { key: "health", icon: <IconHeart />, label: "System Health", group: "SETUP" },
    { key: "config", icon: <IconCog />, label: "Configuration", group: "SETUP" },
    { key: "prompts", icon: <IconBot />, label: "Prompts & context", group: "SETUP" },
    { key: "settings", icon: <IconDoc />, label: "Settings (JSON)", group: "SETUP" },
    { key: "rules", icon: <IconList />, label: "Detection Rules", group: "SETUP" },
    { key: "scan", icon: <IconSearch />, label: "New Scan", group: "ANALYSIS" },
    { key: "scanning", icon: <IconRadar />, label: "Live Dashboard", group: "ANALYSIS" },
    { key: "jobs", icon: <IconFolder />, label: "Scan History", group: "ANALYSIS" },
    { key: "baseline", icon: <IconShield />, label: "Baselines", group: "ANALYSIS" },
    { key: "ssl-pinning", icon: <IconLock />, label: "SSL Pinning Mapper", group: "ANALYSIS" },
    { key: "ssl-bypass", icon: <IconUnlock />, label: "Coming Soon", group: "ANALYSIS" },
  ];

  const groups = ["SETUP", "ANALYSIS"] as const;

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {err && (
        <div className="error-bar" role="alert">
          <IconAlert aria-hidden />
          <div style={{ minWidth: 0 }}>
            <div className="error-bar__title">Request failed</div>
            <p className="error-bar__msg mono">{err}</p>
          </div>
        </div>
      )}

      {appToast && (
        <div className="app-toast app-toast--success" role="status" aria-live="polite">
          <p className="app-toast__text">{appToast}</p>
          <button
            type="button"
            className="app-toast__dismiss"
            onClick={() => {
              setAppToast(null);
              if (appToastTimerRef.current) {
                clearTimeout(appToastTimerRef.current);
                appToastTimerRef.current = null;
              }
            }}
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="layout">
        <aside className="sidenav" aria-label="Primary navigation">
          <div className="sidenav-brand">
            <span className="sidenav-brand-icon" aria-hidden>
              <IconBot size={18} />
            </span>
            <div className="sidenav-brand-text">
              <span className="sidenav-brand-name">APPredator</span>
              <span className="sidenav-brand-sub">Security Console</span>
            </div>
          </div>
          <nav className="sidenav-nav" aria-label="Sections">
            {groups.map((g) => (
              <section key={g} className="nav-group" aria-labelledby={`nav-heading-${g}`}>
                <h2 id={`nav-heading-${g}`} className="nav-group-label">
                  {g}
                </h2>
                <ul className="nav-group-list">
                  {NAV_ITEMS.filter((n) => n.group === g).map(({ key, icon, label }) => (
                    <li key={key} className="nav-group-item">
                      <button
                        type="button"
                        className={`nav-item${tab === key ? " active" : ""}`}
                        onClick={() => setTab(key)}
                        aria-current={tab === key ? "page" : undefined}
                      >
                        <span className="nav-icon" aria-hidden>
                          {icon}
                        </span>
                        <span className="nav-item-label">{label}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </nav>
        </aside>

        <div className="main-column">
          <main id="main-content" className="page-content" tabIndex={-1}>

      {tab === "home" && (
        <HomeDashboard
          onNavigate={(t) => setTab(t as Tab)}
          health={health}
          settingsFileExists={healthDeep?.settings_file_exists ?? null}
          jobsCount={jobs.length}
          onRefreshHealth={async () => {
            await run("homeHealth", async () => {
              await loadHealth();
              await loadHealthDeep();
            });
          }}
          healthBusy={isBusy("homeHealth") || isBusy("homeBoot")}
        />
      )}

      {tab === "wizard" && (
        <>
          <PageHeader
            title="Getting Started"
            desc="Welcome to APPredator. Verify your toolchain and review prerequisites before running your first scan."
            breadcrumb={["Setup", "Getting Started"]}
          />
          <div className="card card-relative">
            <BusyOverlay
              show={isBusy("wizardHealth") || isBusy("wizardSavePaths") || isBusy("wizardPaths")}
              text={
                isBusy("wizardSavePaths") ? "Saving tool paths…" : isBusy("wizardPaths") ? "Loading paths…" : "Running health checks…"
              }
            />
            <h2>Toolchain prerequisites</h2>
            <p className="card-sub">We will verify Java, Apktool, JADX, UberSigner, and your settings file to ensure scans and repack can run.</p>

            <h3>Optional tool paths</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              If Apktool, JADX, or the UberSigner JAR are not on your <code>PATH</code> (or not at the default repo path), set their full paths here (Windows: <code>.bat</code> is supported). These values are persisted to{" "}
              <code>settings.yaml</code>. Use <strong>Browse…</strong> to choose a file; if your browser hides the full path, paste it from Explorer (address bar or{" "}
              <em>Shift + right-click → Copy as path</em>).
            </p>
          <div style={{ marginTop: "0.5rem" }}>
            <label htmlFor="wiz-apktool" style={{ display: "block", marginBottom: "0.25rem" }}>
              Apktool path
            </label>
            <input
              ref={wizardApktoolBrowseRef}
              type="file"
              accept=".bat,.cmd,.exe,.jar,.sh"
              style={{ display: "none" }}
              aria-hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (!f) return;
                const abs = tryFileAbsolutePath(f);
                if (abs) setWizardApktoolPath(abs);
              }}
            />
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
              <input
                id="wiz-apktool"
                type="text"
                style={{ flex: "1 1 280px", minWidth: "200px", maxWidth: "42rem" }}
                value={wizardApktoolPath}
                onChange={(e) => setWizardApktoolPath(e.target.value)}
                placeholder="e.g. E:/tools/apktool/apktool.bat"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
              />
              <button
                type="button"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
                onClick={() => wizardApktoolBrowseRef.current?.click()}
              >
                Browse…
              </button>
            </div>
          </div>
          <div style={{ marginTop: "0.5rem" }}>
            <label htmlFor="wiz-jadx" style={{ display: "block", marginBottom: "0.25rem" }}>
              JADX path
            </label>
            <input
              ref={wizardJadxBrowseRef}
              type="file"
              accept=".bat,.cmd,.exe,.jar,.sh"
              style={{ display: "none" }}
              aria-hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (!f) return;
                const abs = tryFileAbsolutePath(f);
                if (abs) setWizardJadxPath(abs);
              }}
            />
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
              <input
                id="wiz-jadx"
                type="text"
                style={{ flex: "1 1 280px", minWidth: "200px", maxWidth: "42rem" }}
                value={wizardJadxPath}
                onChange={(e) => setWizardJadxPath(e.target.value)}
                placeholder="e.g. E:/tools/jadx/bin/jadx.bat"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
              />
              <button
                type="button"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
                onClick={() => wizardJadxBrowseRef.current?.click()}
              >
                Browse…
              </button>
            </div>
          </div>
          <div style={{ marginTop: "0.5rem" }}>
            <label htmlFor="wiz-ubersigner" style={{ display: "block", marginBottom: "0.25rem" }}>
              UberSigner JAR (uber-apk-signer)
            </label>
            <input
              ref={wizardUbersignerBrowseRef}
              type="file"
              accept=".jar"
              style={{ display: "none" }}
              aria-hidden
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (!f) return;
                const abs = tryFileAbsolutePath(f);
                if (abs) setWizardUbersignerPath(abs);
              }}
            />
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
              <input
                id="wiz-ubersigner"
                type="text"
                style={{ flex: "1 1 280px", minWidth: "200px", maxWidth: "42rem" }}
                value={wizardUbersignerPath}
                onChange={(e) => setWizardUbersignerPath(e.target.value)}
                placeholder="e.g. E:/repo/tools/signer/ubersigner.jar"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
              />
              <button
                type="button"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
                onClick={() => wizardUbersignerBrowseRef.current?.click()}
              >
                Browse…
              </button>
            </div>
          </div>
            <div className="btn-row" style={{ marginTop: "0.85rem" }}>
              <button
                type="button"
                className="btn-primary"
                disabled={isBusy("wizardSavePaths") || isBusy("wizardPaths")}
                onClick={() => void saveWizardToolPaths()}
              >
                Save tool paths
              </button>
            </div>

            <div className="divider" />

            <h3>Run a health check</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              Verify that Java, Apktool, JADX, and UberSigner can be invoked, then confirm the settings file is present.
            </p>
            <div className="btn-row" style={{ marginTop: "0.5rem" }}>
              <button
                type="button"
                className="btn-primary"
                disabled={isBusy("wizardHealth")}
                onClick={() =>
                  void run("wizardHealth", async () => {
                    await loadHealth();
                    await loadHealthDeep();
                  })
                }
              >
                <IconPlay /> {isBusy("wizardHealth") ? "Checking…" : "Run health checks"}
              </button>
            </div>
            {isBusy("wizardHealth") && <CheckSpinner label="Checking toolchain" />}
            {health && !isBusy("wizardHealth") && (
              <div className="health-grid">
                <ToolTile title="Java" data={health.java} />
                <ToolTile title="Apktool" data={health.apktool} />
                <ToolTile title="JADX" data={health.jadx} />
                <ToolTile title="UberSigner" data={health.ubersigner} />
                <div className="health-tile">
                  <h3>LLM Provider</h3>
                  <div className="mono" style={{ color: "var(--text-primary)" }}>{String(health.llm_provider ?? "—")}</div>
                </div>
              </div>
            )}
            {healthDeep && !isBusy("wizardHealth") && (
              <p className="mono hint" style={{ marginTop: "0.75rem" }}>
                Settings file: {healthDeep.settings_file_exists ? (
                  <span className="badge badge-ok">Found</span>
                ) : (
                  <span className="badge badge-danger">Missing</span>
                )}{" "}
                <code>{healthDeep.settings_path}</code>
              </p>
            )}
          </div>
        </>
      )}

      {tab === "health" && (
        <>
          <PageHeader
            title="System Health"
            desc="Live status of Java, Apktool, JADX, UberSigner, and the configured LLM provider."
            breadcrumb={["Setup", "System Health"]}
            actions={
              <>
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={isBusy("health")}
                  onClick={() =>
                    void run("health", async () => {
                      await loadHealth();
                      setServerTuning(
                        (await apiGet("/api/health/server-tuning")) as {
                          items?: { name: string; description: string; configured: boolean }[];
                        }
                      );
                    })
                  }
                >
                  <IconRefresh /> Refresh
                </button>
                <button type="button" className="btn-primary" disabled={isBusy("healthDeep")} onClick={() => void run("healthDeep", loadHealthDeep)}>
                  {isBusy("healthDeep") ? "Checking…" : "Run deep check"}
                </button>
              </>
            }
          />
          <div className="card card-relative">
            <BusyOverlay show={isBusy("health")} text="Checking services…" />
            {isBusy("health") && <CheckSpinner label="Checking Java, Apktool, JADX, UberSigner" />}
            {health && (
              <>
                <div className="health-grid">
                  <ToolTile title="Java" data={health.java} />
                  <ToolTile title="Apktool" data={health.apktool} />
                  <ToolTile title="JADX" data={health.jadx} />
                  <ToolTile title="UberSigner" data={health.ubersigner} />
                  <div className="health-tile">
                    <h3>LLM Provider</h3>
                    <div className="mono" style={{ color: "var(--text-primary)" }}>{String(health.llm_provider ?? "—")}</div>
                  </div>
                </div>
                <details className="collapsible-json">
                  <summary>Raw JSON payload</summary>
                  <pre className="mono">{JSON.stringify(health, null, 2)}</pre>
                </details>
              </>
            )}
            {healthDeep && (
              <details className="collapsible-json">
                <summary>Deep check payload</summary>
                <pre className="mono">{JSON.stringify(healthDeep, null, 2)}</pre>
              </details>
            )}
            {serverTuning?.items && serverTuning.items.length > 0 && (
              <section className="section-card" style={{ marginTop: "1.25rem" }}>
                <div className="section-card__head">
                  <h3 className="section-card__title">Server environment</h3>
                </div>
                <p className="section-card__sub">Process-level variables (not stored in settings.yaml). Configure in your shell, service unit, or container image.</p>
                <div className="server-tuning-grid">
                  {serverTuning.items.map((it) => (
                    <div key={it.name} className="server-tuning-item">
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem" }}>
                        <code>{it.name}</code>
                        <span className={`badge ${it.configured ? "badge-ok" : "badge-neutral"}`}>{it.configured ? "Set" : "Unset"}</span>
                      </div>
                      <p style={{ margin: "0.4rem 0 0", fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>{it.description}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        </>
      )}

      {tab === "settings" && (
        <>
          <PageHeader
            title="Settings (JSON)"
            desc="Edit the raw settings document. Changes are validated against the schema before they are written back to disk."
            breadcrumb={["Setup", "Settings (JSON)"]}
            actions={
              <>
                <button type="button" className="btn-ghost" disabled={isBusy("settings")} onClick={() => void run("settings", loadSettings)}>
                  <IconRefresh /> Reload
                </button>
                <button type="button" className="btn-ghost" disabled={isBusy("validate")} onClick={() => void run("validate", loadValidate)}>
                  Validate only
                </button>
                <button type="button" className="btn-primary" disabled={isBusy("settingsSave")} onClick={() => void saveSettings()}>
                  Save &amp; validate
                </button>
              </>
            }
          />
          <div className="card card-relative">
            <BusyOverlay show={isBusy("settings") || isBusy("settingsSave")} text={isBusy("settingsSave") ? "Saving…" : "Loading…"} />
            {isBusy("settings") && <CheckSpinner label="Loading settings" />}
            <div className="settings-json-wrap">
              <div className="settings-editor-toolbar">
                <button type="button" className="btn-secondary btn-sm" disabled={isBusy("settings")} onClick={() => void formatSettingsJson()}>
                  Format JSON
                </button>
                <button type="button" className="btn-secondary btn-sm" disabled={isBusy("settings")} onClick={() => void run("settings", loadSettings)}>
                  Reset to saved
                </button>
              </div>
              <textarea rows={24} style={{ width: "100%", margin: 0 }} value={settingsText} onChange={(e) => setSettingsText(e.target.value)} spellCheck={false} className="mono" />
            </div>
            {validateResult ? (
              <pre className="mono" style={{ marginTop: "0.75rem", fontSize: "0.8125rem", background: "var(--bg-app-2)", padding: "0.75rem", borderRadius: "8px", border: "1px solid var(--border)", overflow: "auto" }}>
                {JSON.stringify(validateResult, null, 2)}
              </pre>
            ) : null}
          </div>
        </>
      )}

      {tab === "config" && (
        <>
          <PageHeader
            title="Configuration"
            desc="LLM credentials, analysis defaults (persisted in settings.yaml), and scan profiles — organized for day-to-day operations."
            breadcrumb={["Setup", "Configuration"]}
          />
          <div className="card card-relative">
            <BusyOverlay
              show={isBusy("configForm") || isBusy("configApply") || isBusy("llmTest")}
              text={isBusy("llmTest") ? "Testing AI connection…" : isBusy("configApply") ? "Saving config…" : "Loading…"}
            />
            {isBusy("configForm") && <CheckSpinner label="Loading current config" />}
            <div className="config-layout">
            <section className="section-card">
              <div className="section-card__head">
                <h3 className="section-card__title">Language model</h3>
              </div>
              <p className="section-card__sub">
                Provider, model, and credentials map to the <code className="mono">llm:</code> block in <code className="mono">config/settings.yaml</code>. Use{" "}
                <strong>Settings (JSON)</strong> for keys not shown here.
              </p>
            <div className="form-field">
              <label htmlFor="cfg-llm-provider">Provider</label>
            <select
              id="cfg-llm-provider"
              value={cfgProvider}
              onChange={(e) => {
                const v = e.target.value;
                setCfgProvider(v);
                void refreshLlmModelAndCredential(v);
              }}
              disabled={isBusy("configForm")}
              style={{ minWidth: "220px" }}
            >
              {!LLM_PROVIDER_OPTIONS.some((o) => o.id === cfgProvider) && cfgProvider.trim() !== "" && (
                <option value={cfgProvider}>{`Current: ${cfgProvider}`}</option>
              )}
              {LLM_PROVIDER_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
            </div>
            <p className="form-field-hint" style={{ maxWidth: "52rem" }}>{llmKeyHint(cfgProvider)}</p>
          <div style={{ marginTop: "0.5rem" }}>
            <span style={{ display: "block", fontWeight: 600 }}>Model</span>
            {cfgYamlModelKey && (
              <span className="mono" style={{ display: "block", fontSize: "0.78rem", color: "var(--text-secondary)", fontWeight: 400, marginTop: "0.2rem" }}>
                YAML key: <code>llm.{cfgYamlModelKey}</code>
              </span>
            )}
            {llmModelPresets.length > 0 ? (
              <>
                <label htmlFor="cfg-llm-model-preset" className="sr-only">
                  Model preset
                </label>
                <select
                  id="cfg-llm-model-preset"
                  value={llmModelPresets.some((o) => o.value === cfgModel) ? cfgModel : "__custom__"}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === "__custom__") setCfgModel("");
                    else setCfgModel(v);
                  }}
                  style={{ minWidth: "min(100%, 360px)", marginTop: "0.25rem", display: "block" }}
                  disabled={isBusy("configForm") || isBusy("configApply")}
                >
                  {llmModelPresets.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label} — {o.value}
                    </option>
                  ))}
                  <option value="__custom__">Other… (type a custom model id)</option>
                </select>
                {!llmModelPresets.some((o) => o.value === cfgModel) && (
                  <div style={{ marginTop: "0.45rem" }}>
                    <label htmlFor="cfg-llm-model" style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                      Custom model id
                    </label>
                    <input
                      id="cfg-llm-model"
                      value={cfgModel}
                      onChange={(e) => setCfgModel(e.target.value)}
                      placeholder={llmModelPlaceholder(cfgProvider)}
                      className="mono"
                      style={{ minWidth: "min(100%, 360px)", marginTop: "0.2rem", display: "block" }}
                      disabled={isBusy("configForm") || isBusy("configApply")}
                      spellCheck={false}
                      autoComplete="off"
                    />
                  </div>
                )}
                <p className="form-field-hint" style={{ marginTop: "0.35rem", maxWidth: "52rem" }}>
                  Choose a preset or <strong>Other</strong> to enter any model name your provider supports (e.g. a newer Groq or OpenRouter slug).
                </p>
              </>
            ) : (
              <>
                <label htmlFor="cfg-llm-model" className="sr-only">
                  Model id
                </label>
                <input
                  id="cfg-llm-model"
                  value={cfgModel}
                  onChange={(e) => setCfgModel(e.target.value)}
                  placeholder={llmModelPlaceholder(cfgProvider)}
                  style={{ minWidth: "280px", marginTop: "0.25rem" }}
                  disabled={isBusy("configForm") || isBusy("configApply")}
                />
              </>
            )}
          </div>
          {(cfgCredKind === "url" || cfgCredKind === "api_key") && (
            <div style={{ marginTop: "0.65rem" }}>
              <label htmlFor="cfg-llm-cred" style={{ display: "block" }}>
                <span style={{ fontWeight: 600 }}>{cfgCredLabel}</span>
                {cfgYamlCredKey && (
                  <span className="mono" style={{ display: "block", fontSize: "0.78rem", color: "var(--text-secondary)", fontWeight: 400, marginTop: "0.2rem" }}>
                    Maps to <code>llm.{cfgYamlCredKey}</code>
                    {cfgYamlModelKey ? (
                      <>
                        {" "}
                        · model: <code>llm.{cfgYamlModelKey}</code>
                      </>
                    ) : null}{" "}
                    {cfgSettingsPath ? (
                      <>
                        {" "}
                        · file: <code>{cfgSettingsPath}</code>
                      </>
                    ) : (
                      <> in <code>config/settings.yaml</code></>
                    )}
                  </span>
                )}
              </label>
              <input
                id="cfg-llm-cred"
                type={cfgCredKind === "url" ? "url" : "password"}
                autoComplete="off"
                value={cfgCredValue}
                onChange={(e) => setCfgCredValue(e.target.value)}
                placeholder={
                  cfgCredKind === "url"
                    ? "http://localhost:11434"
                    : cfgCredConfigured
                      ? `Leave blank to keep current llm.${cfgYamlCredKey}`
                      : cfgYamlCredKey
                        ? `Paste value for llm.${cfgYamlCredKey}`
                        : "Paste API key"
                }
                style={{ display: "block", marginTop: "0.25rem", width: "min(100%, 36rem)" }}
                disabled={isBusy("configForm") || isBusy("configApply")}
              />
              {cfgCredKind === "api_key" && cfgCredConfigured && cfgSecretLength > 0 && cfgSecretPreview && (
                <p
                  className="mono"
                  style={{ margin: "0.4rem 0 0", fontSize: "0.82rem", color: "var(--ok)", wordBreak: "break-all" }}
                  title="Value is read from settings.yaml on the server. The input stays empty for security; type only when replacing the key."
                >
                  In sync with <code>config/settings.yaml</code>: <code>llm.{cfgYamlCredKey}</code> is set ({cfgSecretLength} chars). Preview:{" "}
                  <span style={{ letterSpacing: "0.02em" }}>{cfgSecretPreview}</span>
                </p>
              )}
              {cfgCredKind === "api_key" && cfgCredConfigured && cfgSecretLength === 0 && (
                <p style={{ margin: "0.4rem 0 0", fontSize: "0.82rem", color: "var(--warn)" }}>
                  YAML marks a key as present but value looks empty after trim — check <code>llm.{cfgYamlCredKey}</code>.
                </p>
              )}
              {cfgCredKind === "api_key" && !cfgCredConfigured && (
                <p style={{ margin: "0.4rem 0 0", fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                  No value in <code>llm.{cfgYamlCredKey}</code> yet — paste a key and click Apply changes.
                </p>
              )}
              {cfgCredKind === "api_key" && cfgCredConfigured && (
                <label style={{ display: "block", marginTop: "0.4rem", fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                  <input
                    type="checkbox"
                    checked={cfgClearApiKey}
                    onChange={(e) => setCfgClearApiKey(e.target.checked)}
                    disabled={isBusy("configForm") || isBusy("configApply")}
                  />{" "}
                  Remove saved API key from settings
                </label>
              )}
            </div>
          )}
          <p style={{ margin: "0.45rem 0 0", fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Other keys and options: <strong>Settings JSON</strong> or <code>config/settings.yaml</code>.
          </p>
          <div className="btn-row" style={{ marginTop: "0.85rem" }}>
            <button type="button" className="btn-ghost" disabled={isBusy("llmTest") || isBusy("configApply")} onClick={() => void testLlmConnection()}>
              <IconPlay /> {isBusy("llmTest") ? "Testing…" : "Test AI connection"}
            </button>
            <span className="hint" style={{ maxWidth: "36rem" }}>
              Uses the <strong>saved</strong> <code>llm.*</code> values on the server. Click <strong>Save configuration</strong> first if you edited the provider, model, or API key above.
            </span>
          </div>
          {llmTestResult && (
            <div
              className="mono"
              style={{
                marginTop: "0.75rem",
                padding: "0.75rem 0.85rem",
                borderRadius: "10px",
                border: `1px solid ${llmTestResult.ok ? "#bbf7d0" : "#fecaca"}`,
                background: llmTestResult.ok ? "#f0fdf4" : "#fef2f2",
                fontSize: "0.8125rem",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                animation: "fadeIn .25s ease",
              }}
            >
              <span className={`badge ${llmTestResult.ok ? "badge-ok" : "badge-danger"}`}>
                {llmTestResult.ok ? "Connected" : "Not connected"}
              </span>
              {llmTestResult.provider != null && llmTestResult.provider !== "" && (
                <>
                  {" "}
                  · provider: <code>{llmTestResult.provider}</code>
                </>
              )}
              {typeof llmTestResult.latency_ms === "number" && (
                <>
                  {" "}
                  · {llmTestResult.latency_ms} ms
                </>
              )}
              {llmTestResult.model != null && llmTestResult.model !== "" && (
                <>
                  {" "}
                  · model: <code>{llmTestResult.model}</code>
                </>
              )}
              {llmTestResult.endpoint != null && llmTestResult.endpoint !== "" && (
                <>
                  {" "}
                  · <code>{llmTestResult.endpoint}</code>
                </>
              )}
              <div style={{ marginTop: "0.35rem" }}>{llmTestResult.message ?? "—"}</div>
            </div>
          )}
            </section>

            <div className="divider" />

            <section className="section-card">
              <div className="section-card__head">
                <h3 className="section-card__title">Analysis pipeline</h3>
              </div>
              <p className="section-card__sub">
                Decompiler and filter modes plus runtime feature flags under <code className="mono">analysis.*</code>. These defaults apply to CLI and web scans unless overridden per job.
              </p>
            <div className="form-row">
              <div className="form-field">
                <label>Filter mode</label>
                <select value={filterMode} onChange={(e) => setFilterMode(e.target.value)} style={{ minWidth: "12rem" }}>
                  <option value="static_only">Static analysis only</option>
                  <option value="llm_only">LLM only</option>
                  <option value="hybrid">Hybrid (recommended)</option>
                </select>
              </div>
              <div className="form-field">
                <label>Decompiler mode</label>
                <select value={decompilerMode} onChange={(e) => setDecompilerMode(e.target.value)} style={{ minWidth: "12rem" }}>
                  <option value="apktool">Apktool (smali)</option>
                  <option value="jadx">JADX (Java)</option>
                  <option value="hybrid">Hybrid (recommended)</option>
                </select>
              </div>
            </div>
            <div className="toggle-grid">
              <label className="toggle-item">
                <input type="checkbox" checked={attackSurface} onChange={(e) => setAttackSurface(e.target.checked)} disabled={isBusy("configForm") || isBusy("configApply")} />
                <span>
                  <strong>Attack surface map</strong>
                  <span className="desc">Emit structured map of entry points for reviewers.</span>
                </span>
              </label>
              <label className="toggle-item">
                <input type="checkbox" checked={contextInjection} onChange={(e) => setContextInjection(e.target.checked)} disabled={isBusy("configForm") || isBusy("configApply")} />
                <span>
                  <strong>Cross-reference context</strong>
                  <span className="desc">Inject call-graph context into LLM prompts (recommended).</span>
                </span>
              </label>
              <label className="toggle-item">
                <input type="checkbox" checked={generateExploit} onChange={(e) => setGenerateExploit(e.target.checked)} disabled={isBusy("configForm") || isBusy("configApply")} />
                <span>
                  <strong>Generate exploit / PoC</strong>
                  <span className="desc">When enabled, the engine attempts PoC scripts for confirmed issues (heavier run).</span>
                </span>
              </label>
              <label className="toggle-item">
                <input type="checkbox" checked={scanLibraries} onChange={(e) => setScanLibraries(e.target.checked)} disabled={isBusy("configForm") || isBusy("configApply")} />
                <span>
                  <strong>Scan third-party libraries</strong>
                  <span className="desc">Include androidx, okhttp, etc. Wider scope; may increase tokens and time.</span>
                </span>
              </label>
            </div>

            {cfgProvider === "deepseek" && (
              <div style={{ marginTop: "1rem", padding: "1rem", borderRadius: "10px", border: "1px solid var(--border)", background: "var(--bg-app-2)" }}>
                <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.92rem", fontWeight: 700 }}>DeepSeek client options</h4>
                <p className="hint" style={{ margin: "0 0 0.75rem" }}>
                  Optional overrides for the OpenAI-compatible DeepSeek API. Cleared fields remove the YAML key on save (client defaults apply).
                </p>
                <div className="form-field">
                  <label htmlFor="ds-base">Base URL</label>
                  <input
                    id="ds-base"
                    className="mono"
                    style={{ width: "min(100%, 36rem)" }}
                    value={dsBaseUrl}
                    onChange={(e) => setDsBaseUrl(e.target.value)}
                    placeholder="https://api.deepseek.com (default if empty)"
                    disabled={isBusy("configForm") || isBusy("configApply")}
                  />
                </div>
                <div className="form-field" style={{ marginTop: "0.65rem" }}>
                  <label htmlFor="ds-effort">Reasoning effort</label>
                  <input
                    id="ds-effort"
                    value={dsReasoning}
                    onChange={(e) => setDsReasoning(e.target.value)}
                    placeholder="e.g. high"
                    style={{ width: "min(100%, 16rem)" }}
                    disabled={isBusy("configForm") || isBusy("configApply")}
                  />
                </div>
                <div className="form-field" style={{ marginTop: "0.65rem" }}>
                  <label htmlFor="ds-think">Thinking mode</label>
                  <select
                    id="ds-think"
                    value={dsThinking}
                    onChange={(e) => setDsThinking(e.target.value as "unset" | "on" | "off")}
                    style={{ minWidth: "14rem" }}
                    disabled={isBusy("configForm") || isBusy("configApply")}
                  >
                    <option value="unset">Default (client)</option>
                    <option value="on">Forced on</option>
                    <option value="off">Forced off</option>
                  </select>
                </div>
              </div>
            )}
            </section>

            <div className="btn-row" style={{ marginTop: "1rem" }}>
              <button type="button" className="btn-primary" disabled={isBusy("configApply")} onClick={() => void applyProviderModel()}>
                {isBusy("configApply") ? "Saving…" : "Save configuration"}
              </button>
              <span className="hint">Persists LLM, analysis flags, and DeepSeek options above.</span>
            </div>

            <div className="divider" />

            <section className="section-card">
              <div className="section-card__head">
                <h3 className="section-card__title">Scan profiles</h3>
              </div>
              <p className="section-card__sub">Named YAML presets under <code className="mono">config/profiles/</code>. Switching copies the chosen file over the active <code className="mono">settings.yaml</code>.</p>
            <p className="hint" style={{ marginTop: 0 }}>
              Available profiles: <span className="mono" style={{ color: "var(--text-primary)" }}>{profiles.length ? profiles.join(", ") : "(none)"}</span>
            </p>
            <div className="form-row" style={{ marginTop: "0.5rem" }}>
              <input placeholder="New profile name" value={profileNewName} onChange={(e) => setProfileNewName(e.target.value)} style={{ minWidth: "14rem" }} />
              <input placeholder="Copy from (optional)" value={profileCopyFrom} onChange={(e) => setProfileCopyFrom(e.target.value)} style={{ minWidth: "14rem" }} />
              <button type="button" className="btn-ghost" disabled={isBusy("profileCreate")} onClick={() => void createProfile()}>
                Create
              </button>
            </div>
            <div className="form-row" style={{ marginTop: "0.6rem" }}>
              <select value={profileSwitch} onChange={(e) => setProfileSwitch(e.target.value)} style={{ minWidth: "14rem" }}>
                <option value="">Switch active profile…</option>
                {profiles.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
              <button type="button" className="btn-ghost" disabled={isBusy("profileSwitch") || !profileSwitch} onClick={() => void switchProfile()}>
                Switch
              </button>
            </div>
            {profiles.length > 0 && (
              <ul className="job-list" style={{ marginTop: "0.85rem" }}>
                {profiles.map((p) => (
                  <li key={p} className="job-item" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.55rem 0.8rem" }}>
                    <code>{p}</code>
                    <button type="button" className="btn-sm btn-danger" disabled={isBusy("profileDel")} onClick={() => void deleteProfile(p)}>
                      <IconTrash /> Delete
                    </button>
                  </li>
                ))}
              </ul>
            )}
            </section>
            </div>
          </div>
        </>
      )}

      {tab === "prompts" && (
        <>
          <PageHeader
            title="Prompts & retrieval context"
            desc="Edit prompt templates under config/prompts and retrieval documents under config/knowledge_base (for example MASVS mappings). The scanner injects these into LLM calls; saved changes apply on the next scan without restarting the server."
            breadcrumb={["Setup", "Prompts & context"]}
          />
          <PromptsWorkspace isBusy={isBusy} run={run} />
        </>
      )}

      {tab === "rules" && (
        <>
          <PageHeader
            title="Detection Rules"
            desc="Enable or disable individual static-analysis rules. Disabled rules will be skipped during scans."
            breadcrumb={["Setup", "Detection Rules"]}
            actions={
              <button type="button" className="btn-ghost" disabled={isBusy("rules") || isBusy("ruleToggle")} onClick={() => void run("rules", loadRules)}>
                <IconRefresh /> Refresh
              </button>
            }
          />
          <div className="card card-relative">
            <BusyOverlay show={isBusy("rules") || isBusy("ruleToggle")} text={isBusy("ruleToggle") ? "Updating rule…" : "Loading rules…"} />
            {isBusy("rules") && <CheckSpinner label="Loading rule metadata" />}
            <table className="rules-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Status</th>
                <th>Enable</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>
                    <span className={`badge ${r.enabled ? "badge-ok" : "badge-neutral"}`}>
                      {r.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <button
                      type="button"
                      className={`btn-sm ${r.enabled ? "btn-success" : "btn-ghost"}`}
                      disabled={isBusy("ruleToggle") || r.enabled}
                      onClick={() => setRuleEnabled(r.id, true)}
                      title="Enable this rule"
                    >
                      On
                    </button>{" "}
                    <button
                      type="button"
                      className={`btn-sm ${!r.enabled ? "btn-danger" : "btn-ghost"}`}
                      disabled={isBusy("ruleToggle") || !r.enabled}
                      onClick={() => setRuleEnabled(r.id, false)}
                      title="Disable this rule"
                    >
                      Off
                    </button>
                  </td>
                  <td style={{ color: "var(--text-secondary)" }}>{r.description || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </>
      )}

      {tab === "scanning" && (
        <>
          <PageHeader
            title="Live Scan Dashboard"
            desc="Real-time monitoring of the selected scan — persisted findings, severity breakdown, category distribution, and discovery timeline updated every two seconds."
            breadcrumb={["Analysis", "Live Dashboard"]}
            actions={
              scanJobDetail?.status === "running" ? (
                <span className="badge badge-ok" style={{ padding: "0.3rem 0.7rem", display: "inline-flex", alignItems: "center", gap: "0.5rem" }}>
                  <span className="live-dot" /> Live
                </span>
              ) : scanJobDetail?.status ? (
                <span className={`badge ${scanJobDetail.status === "completed" ? "badge-ok" : scanJobDetail.status === "failed" ? "badge-danger" : "badge-neutral"}`}>
                  {String(scanJobDetail.status)}
                </span>
              ) : null
            }
          />
          <div className="card card-relative">
            <BusyOverlay show={isBusy("scanningJobs")} text="Loading jobs…" />
            <div className="scan-toolbar">
              <label className="input-col">
                <span>Select Job</span>
                <select value={jobs.some((j) => j.id === scanningJobId) ? scanningJobId : ""} onChange={(e) => setScanningJobId(e.target.value)}>
                  <option value="">— choose a job —</option>
                  {jobs.map((j) => (
                    <option key={j.id} value={j.id}>
                      {j.id.slice(0, 8)}… · {j.status}
                      {j.meta?.filename ? ` · ${j.meta.filename}` : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label className="input-col input-grow">
                <span>Or paste Job ID</span>
                <input type="text" className="mono" placeholder="00000000-0000-0000-0000-000000000000" value={scanningJobId} onChange={(e) => setScanningJobId(e.target.value.trim())} />
              </label>
              <button type="button" className="btn-primary" disabled={!scanningJobId || scanningWsBusy} onClick={() => connectScanningLogs(scanningJobId)}>
                {scanningWsBusy ? "Streaming…" : "Stream log"}
              </button>
              <label className="inline-check">
                <input type="checkbox" checked={scanningAutoScroll} onChange={(e) => setScanningAutoScroll(e.target.checked)} />
                Auto-scroll
              </label>
            </div>

            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-card__label">Total Findings</div>
                <div className="stat-card__value">{liveSummary?.total_count ?? 0}</div>
                <div className="stat-card__hint">Across all severities</div>
              </div>
              <div className="stat-card">
                <div className="stat-card__label" style={{ color: "var(--sev-critical-fg)" }}>Vulnerable</div>
                <div className="stat-card__value">{liveSummary?.vulnerable_count ?? 0}</div>
                <div className="stat-card__hint">Confirmed by analysis</div>
              </div>
              <div className="stat-card">
                <div className="stat-card__label">Log Lines</div>
                <div className="stat-card__value">{scanningLogs.length}</div>
                <div className="stat-card__hint">Streamed via WebSocket</div>
              </div>
              <div className="stat-card">
                <div className="stat-card__label">Job Status</div>
                <div className="stat-card__value" style={{ fontSize: "1.1rem", textTransform: "capitalize" }}>
                  {scanJobDetail?.status ? String(scanJobDetail.status) : "—"}
                </div>
                <div className="stat-card__hint">Latest known state</div>
              </div>
            </div>

            <div className="charts-grid">
              <SeverityBarChart summary={liveSummary} />
              <CategoryDonutChart summary={liveSummary} />
              <FindingsTimelineChart points={liveTimeline} />
            </div>

            <LiveFindingsTable items={liveFindings} />

            {scanJobDetail?.status === "completed" && (
              <div className="btn-row" style={{ marginTop: "1rem" }}>
                <a className="badge badge-info" style={{ padding: "0.35rem 0.75rem", textDecoration: "none" }} href={`/api/scans/${encodeURIComponent(scanningJobId)}/artifacts?format=json`}>
                  <IconDownload /> &nbsp; JSON Report
                </a>
                <a className="badge badge-info" style={{ padding: "0.35rem 0.75rem", textDecoration: "none" }} href={`/api/scans/${encodeURIComponent(scanningJobId)}/artifacts?format=sarif`}>
                  <IconDownload /> &nbsp; SARIF
                </a>
                <a className="badge badge-info" style={{ padding: "0.35rem 0.75rem", textDecoration: "none" }} href={`/api/scans/${encodeURIComponent(scanningJobId)}/artifacts?format=html`} target="_blank" rel="noreferrer">
                  <IconDownload /> &nbsp; HTML Report
                </a>
              </div>
            )}

            <h3 style={{ marginTop: "1.5rem" }}>Scan Log <span className="muted" style={{ fontSize: "0.78rem", fontWeight: 400 }}>({scanningLogs.length} lines)</span></h3>
            <pre ref={scanningLogPreRef} className="log-panel">
              {scanningLogs.length
                ? scanningLogs.join("\n")
                : scanningJobId
                  ? "(No log lines yet — start a scan or pick another job)"
                  : "Select a job ID above to begin streaming."}
            </pre>
          </div>
        </>
      )}

      {tab === "ssl-bypass" && (
        <>
          <style>{`
            @keyframes pulse-glow {
              0%, 100% {
                transform: scale(1);
                filter: drop-shadow(0 0 15px rgba(59, 130, 246, 0.6));
              }
              50% {
                transform: scale(1.08);
                filter: drop-shadow(0 0 25px rgba(59, 130, 246, 0.9));
              }
            }
            .coming-soon-gradient {
              background: linear-gradient(135deg, #a78bfa 0%, #3b82f6 50%, #60a5fa 100%);
              -webkit-background-clip: text;
              -webkit-text-fill-color: transparent;
            }
          `}</style>
          <PageHeader
            title="Bypass SSL Pinning & Repack"
            desc="Decode with Apktool, apply NSC + Smali stubs from static detection, rebuild, and re-sign with UberSigner (uber-apk-signer). Use only on apps you own or are authorized to test."
            breadcrumb={["Analysis", "Bypass SSL Pinning & Repack"]}
          />
          <div className="card" style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: "6rem 2rem",
            textAlign: "center",
            background: "rgba(255, 255, 255, 0.02)",
            backdropFilter: "blur(12px)",
            borderRadius: "20px",
            border: "1px solid rgba(255, 255, 255, 0.06)",
            boxShadow: "0 20px 50px rgba(0, 0, 0, 0.3)",
            marginTop: "2rem",
            position: "relative",
            overflow: "hidden"
          }}>
            <div style={{
              position: "absolute",
              width: "150px",
              height: "150px",
              background: "radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%, transparent 70%)",
              top: "10%",
              left: "10%",
              pointerEvents: "none"
            }} />
            <div style={{
              position: "absolute",
              width: "200px",
              height: "200px",
              background: "radial-gradient(circle, rgba(167, 139, 250, 0.12) 0%, transparent 70%)",
              bottom: "10%",
              right: "10%",
              pointerEvents: "none"
            }} />
            
            <div style={{
              fontSize: "4.5rem",
              marginBottom: "2rem",
              animation: "pulse-glow 3s ease-in-out infinite",
              userSelect: "none"
            }}>
              🚀
            </div>
            
            <h2 className="coming-soon-gradient" style={{
              fontSize: "2.25rem",
              fontWeight: 800,
              letterSpacing: "-0.025em",
              marginBottom: "1.25rem"
            }}>
              Coming Soon
            </h2>
            
            <p style={{
              maxWidth: "520px",
              color: "rgba(255, 255, 255, 0.6)",
              lineHeight: 1.7,
              fontSize: "1.1rem",
              margin: "0 0 2rem 0"
            }}>
              We are engineering a robust, fully-automated Bypass SSL Pinning &amp; Repack pipeline. Stay tuned for a seamless decompile, patch, and rebuild experience!
            </p>
            
            <div style={{
              display: "flex",
              gap: "1rem",
              alignItems: "center"
            }}>
              <span className="badge" style={{
                background: "rgba(59, 130, 246, 0.15)",
                color: "#60a5fa",
                border: "1px solid rgba(59, 130, 246, 0.3)",
                padding: "0.4rem 0.8rem",
                borderRadius: "9999px",
                fontSize: "0.85rem",
                fontWeight: 600
              }}>
                Phase 2 Development
              </span>
              <span className="badge" style={{
                background: "rgba(167, 139, 250, 0.15)",
                color: "#a78bfa",
                border: "1px solid rgba(167, 139, 250, 0.3)",
                padding: "0.4rem 0.8rem",
                borderRadius: "9999px",
                fontSize: "0.85rem",
                fontWeight: 600
              }}>
                Automated Smali
              </span>
            </div>
          </div>
        </>
      )}

      <div hidden={tab !== "ssl-pinning"}>
        <PageHeader
          title="SSL Pinning Mapper"
          desc="Static map of certificate pinning stacks (OkHttp, TrustKit, Cronet, Flutter, Network Security Config), evidence paths, and a starter Frida script."
          breadcrumb={["Analysis", "SSL Pinning Mapper"]}
        />
        <SslPinningMapperPanel isBusy={isBusy} run={run} setErr={setErr} onSuccessToast={showAppToast} />
      </div>

      {tab === "scan" && (
        <>
          <PageHeader
            title="New Scan"
            desc="Upload an APK or XAPK file and configure scan options. The job will appear on the Live Dashboard as soon as it starts."
            breadcrumb={["Analysis", "New Scan"]}
          />
          <ol className="scan-steps" aria-label="Scan workflow">
            <li className={!scanPendingFile ? "is-active" : ""}>
              <span className="scan-steps__num">1</span> Upload package
            </li>
            <li className={scanPendingFile ? "is-active" : ""}>
              <span className="scan-steps__num">2</span> Configure &amp; review
            </li>
            <li className={scanPendingFile ? "is-active" : ""}>
              <span className="scan-steps__num">3</span> Start scan
            </li>
          </ol>
          <div className="card card-relative">
            <BusyOverlay show={isBusy("scan")} text="Uploading and starting scan…" />

            <h3>Upload package</h3>
            <label
              htmlFor="scan-apk-input"
              className={`file-drop file-drop--scan${scanApkDragActive ? " file-drop--drag-active" : ""}`}
              onDragEnter={(e) => {
                e.preventDefault();
                e.stopPropagation();
                scanApkDragNest.current += 1;
                if (scanApkDragNest.current === 1) setScanApkDragActive(true);
              }}
              onDragLeave={(e) => {
                e.preventDefault();
                e.stopPropagation();
                scanApkDragNest.current = Math.max(0, scanApkDragNest.current - 1);
                if (scanApkDragNest.current === 0) setScanApkDragActive(false);
              }}
              onDragOver={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
              onDrop={(e) => {
                e.preventDefault();
                e.stopPropagation();
                scanApkDragNest.current = 0;
                setScanApkDragActive(false);
                const f = e.dataTransfer.files?.[0];
                if (!f) return;
                const name = f.name.toLowerCase();
                if (name.endsWith(".apk") || name.endsWith(".xapk")) setScanPendingFile(f);
              }}
            >
              <input
                key={scanFileInputKey}
                id="scan-apk-input"
                type="file"
                accept=".apk,.xapk"
                className="file-drop__native-input"
                disabled={isBusy("scan")}
                onChange={(e) => {
                  const f = e.target.files?.[0] ?? null;
                  setScanPendingFile(f);
                }}
              />
              <div className="file-drop__scan-inner">
                <div className="file-drop__scan-icon" aria-hidden>
                  <IconUpload size={28} />
                </div>
                <div className="file-drop__scan-copy">
                  <span className="file-drop__scan-title">Drop APK or XAPK here</span>
                  <span className="file-drop__scan-sub hint">or click anywhere in this area — max size follows server limits (multipart upload).</span>
                </div>
                <div className="file-drop__scan-actions">
                  <span className="file-drop__scan-btn">Select package…</span>
                  <span className="file-drop__scan-formats mono">.apk · .xapk</span>
                </div>
              </div>
            </label>
            {scanPendingFile && (
              <p className="file-drop__selected mono hint">
                Selected: <strong className="file-drop__selected-name">{scanPendingFile.name}</strong>{" "}
                <span className="file-drop__selected-size">({Math.round(scanPendingFile.size / 1024)} KB)</span>
              </p>
            )}

            <div className="divider" />

            <section className="section-card" style={{ marginTop: 0 }}>
              <div className="section-card__head">
                <h3 className="section-card__title">Run options</h3>
              </div>
              <p className="section-card__sub">
                Per-job flags (mirrors CLI). Defaults in <code className="mono">analysis.*</code> still apply unless you override exploit / libraries here.
              </p>
              <div className="scan-options-grid">
                <label className="toggle-item">
                  <input type="checkbox" checked={scanVerbose} onChange={(e) => setScanVerbose(e.target.checked)} disabled={isBusy("scan")} />
                  <span>
                    <strong>Verbose logging</strong>
                    <span className="desc">More detail in job logs.</span>
                  </span>
                </label>
                <label className="toggle-item">
                  <input type="checkbox" checked={scanNoDecompile} onChange={(e) => setScanNoDecompile(e.target.checked)} disabled={isBusy("scan")} />
                  <span>
                    <strong>Skip decompile</strong>
                    <span className="desc">Reuse existing output when applicable.</span>
                  </span>
                </label>
                <label className="toggle-item">
                  <input type="checkbox" checked={scanGenExploit} onChange={(e) => setScanGenExploit(e.target.checked)} disabled={isBusy("scan")} />
                  <span>
                    <strong>Generate exploit (this job)</strong>
                    <span className="desc">One-shot override; can also enable globally in Configuration.</span>
                  </span>
                </label>
                <label className="toggle-item">
                  <input type="checkbox" checked={scanLibs} onChange={(e) => setScanLibs(e.target.checked)} disabled={isBusy("scan")} />
                  <span>
                    <strong>Scan libraries (this job)</strong>
                    <span className="desc">Include third-party packages for this run only.</span>
                  </span>
                </label>
              </div>
              <div className="form-row" style={{ marginTop: "1rem" }}>
                <div className="form-field">
                  <label>Profile name</label>
                  <input value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} placeholder="optional — YAML in config/profiles/" disabled={isBusy("scan")} style={{ minWidth: "12rem" }} />
                </div>
                <div className="form-field">
                  <label>Output directory override</label>
                  <input value={scanOutput} onChange={(e) => setScanOutput(e.target.value)} placeholder="optional" disabled={isBusy("scan")} style={{ minWidth: "14rem" }} />
                </div>
              </div>
              <div className="form-field" style={{ marginTop: "0.65rem" }}>
                <label htmlFor="scan-rules-json">Rules filter (JSON array)</label>
                <input
                  id="scan-rules-json"
                  className="mono"
                  value={scanRulesRaw}
                  onChange={(e) => setScanRulesRaw(e.target.value)}
                  placeholder='e.g. ["sql_injection","exported_components"] or leave empty for all enabled rules'
                  disabled={isBusy("scan")}
                  style={{ width: "100%", maxWidth: "48rem" }}
                />
              </div>
            </section>

            <div className="divider" />

            <h3 style={{ margin: "0 0 0.35rem", fontSize: "1rem" }}>Advanced: settings overrides</h3>
            <p className="hint" style={{ marginTop: 0 }}>
              JSON object merged into settings for this job only (<code>settings_overrides</code>). Use <code>null</code> for none.
            </p>
            <div className="settings-json-wrap">
              <textarea rows={8} style={{ width: "100%", margin: 0 }} value={scanOverridesJson} onChange={(e) => setScanOverridesJson(e.target.value)} disabled={isBusy("scan")} spellCheck={false} className="mono" />
            </div>

            <div className="btn-row" style={{ marginTop: "1rem" }}>
              <button type="button" className="btn-primary" disabled={!scanPendingFile || isBusy("scan")} onClick={() => void startScan()}>
                <IconPlay /> {isBusy("scan") ? "Starting…" : "Start scan"}
              </button>
              <button
                type="button"
                className="btn-ghost"
                disabled={!scanPendingFile || isBusy("scan")}
                onClick={() => {
                  setScanPendingFile(null);
                  setScanFileInputKey((k) => k + 1);
                }}
              >
                Clear file
              </button>
            </div>
          </div>
        </>
      )}

      {tab === "jobs" && (
        <>
          <PageHeader
            title="Scan History"
            desc="Browse, stream, and manage previous scan jobs. Reports are available in JSON, SARIF, and HTML formats."
            breadcrumb={["Analysis", "Scan History"]}
            actions={
              <button type="button" className="btn-ghost" disabled={isBusy("jobs")} onClick={() => void run("jobs", loadJobs)}>
                <IconRefresh /> Refresh
              </button>
            }
          />
          <div className="card card-relative">
            <BusyOverlay show={isBusy("jobs") || isBusy("jobDel")} text="Loading jobs…" />
            {isBusy("jobs") && <CheckSpinner label="Loading job list" />}
            {lastJob && (
              <div style={{ marginBottom: "0.9rem", display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                <span className="hint">Last created job:</span>
                <code>{lastJob}</code>
                <button type="button" className="btn-sm btn-ghost" disabled={wsBusy} onClick={() => connectLogs(lastJob)}>
                  {wsBusy ? "Streaming…" : "Stream logs"}
                </button>
              </div>
            )}
            {jobs.length === 0 && !isBusy("jobs") ? (
              <div className="empty-chart" style={{ minHeight: "120px", flexDirection: "column", gap: "0.4rem" }}>
                <IconFolder size={28} />
                <span>No scan jobs yet. Start a scan from the <strong>New Scan</strong> tab.</span>
              </div>
            ) : (
              <ul className="job-list">
                {jobs.map((j) => (
                  <li key={j.id} className="job-item">
                    <div className="job-item-head">
                      <code className="job-item-id">{j.id}</code>
                      <span
                        className={`badge ${
                          j.status === "completed" ? "badge-ok" : j.status === "failed" ? "badge-danger" : j.status === "running" ? "badge-info" : "badge-neutral"
                        }`}
                      >
                        {j.status === "running" && <span className="live-dot" style={{ marginRight: "0.35rem" }} />}
                        {j.status}
                      </span>
                    </div>
                    {j.meta?.filename && (
                      <div className="job-item-meta mono">file: {j.meta.filename}</div>
                    )}
                    {(j.created_at || j.updated_at) && (
                      <div className="job-item-meta mono">
                        {j.created_at && <>created {j.created_at}</>}
                        {j.updated_at && <> · updated {j.updated_at}</>}
                      </div>
                    )}
                    {j.error && (
                      <div className="status-bad mono" style={{ fontSize: "0.78rem", marginTop: "0.4rem" }}>{j.error}</div>
                    )}
                    <div className="job-item-actions">
                      {j.report_json_path && (
                        <>
                          <a className="badge badge-info" style={{ padding: "0.3rem 0.6rem", textDecoration: "none" }} href={`/api/scans/${j.id}/artifacts?format=json`}>
                            <IconDownload /> &nbsp; JSON
                          </a>
                          <a className="badge badge-info" style={{ padding: "0.3rem 0.6rem", textDecoration: "none" }} href={`/api/scans/${j.id}/artifacts?format=sarif`}>
                            <IconDownload /> &nbsp; SARIF
                          </a>
                          <a className="badge badge-info" style={{ padding: "0.3rem 0.6rem", textDecoration: "none" }} href={`/api/scans/${j.id}/artifacts?format=html`} target="_blank" rel="noreferrer">
                            <IconDownload /> &nbsp; HTML
                          </a>
                        </>
                      )}
                      <button type="button" className="btn-sm btn-danger" disabled={isBusy("jobDel")} onClick={() => void deleteJob(j.id)}>
                        <IconTrash /> Remove
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {logs.length > 0 && (
              <pre className="log-panel" style={{ marginTop: "1rem" }}>
                {logs.join("\n")}
              </pre>
            )}
          </div>
        </>
      )}

      {tab === "baseline" && (
        <>
          <PageHeader
            title="Baselines"
            desc="Suppress known findings by fingerprint. Useful for triaging accepted risks across multiple scans of the same application."
            breadcrumb={["Analysis", "Baselines"]}
            actions={
              <button type="button" className="btn-ghost" disabled={isBusy("baseline")} onClick={() => void run("baseline", loadBaselines)}>
                <IconRefresh /> Refresh
              </button>
            }
          />
          <div className="card card-relative">
            <BusyOverlay
              show={isBusy("baseline") || isBusy("baselineAdd") || isBusy("baselineDel")}
              text={isBusy("baselineAdd") ? "Saving…" : isBusy("baselineDel") ? "Removing…" : "Loading…"}
            />
            {isBusy("baseline") && <CheckSpinner label="Loading baselines" />}

            <h3>Add baseline entry</h3>
            <BaselineForm onAdd={(fp, app, reason) => void addBaseline(fp, app, reason)} busy={isBusy("baselineAdd")} />

            <h3>Existing entries</h3>
            {(baselines?.entries || []).length === 0 ? (
              <p className="hint">No baseline entries yet.</p>
            ) : (
              <ul className="job-list">
                {(baselines?.entries || []).map((e) => (
                  <li key={e.id} className="job-item">
                    <div className="job-item-head">
                      <code className="job-item-id">{e.fingerprint.slice(0, 24)}…</code>
                      <span className="badge badge-neutral">{e.application_id}</span>
                    </div>
                    <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", marginTop: "0.25rem" }}>{e.reason}</div>
                    {e.created_at && (
                      <div className="job-item-meta mono">added {e.created_at}</div>
                    )}
                    <div className="job-item-actions">
                      <button
                        type="button"
                        className="btn-sm btn-danger"
                        disabled={isBusy("baselineDel")}
                        onClick={() =>
                          void run("baselineDel", async () => {
                            await apiDelete(`/api/baselines/${e.id}`);
                            await loadBaselines();
                          })
                        }
                      >
                        <IconTrash /> Delete
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
        </main>
        </div>
      </div>
    </div>
  );
}

function BaselineForm({ onAdd, busy }: { onAdd: (fp: string, app: string, reason: string) => void; busy: boolean }) {
  const [fp, setFp] = useState("");
  const [app, setApp] = useState("");
  const [reason, setReason] = useState("");
  const canSubmit = fp.trim() && app.trim() && !busy;
  return (
    <div className="form-row" style={{ marginTop: "0.55rem", marginBottom: "1rem" }}>
      <div className="form-field">
        <label>Fingerprint</label>
        <input placeholder="sha256 fingerprint" value={fp} onChange={(e) => setFp(e.target.value)} disabled={busy} style={{ minWidth: "18rem" }} />
      </div>
      <div className="form-field">
        <label>Application ID</label>
        <input placeholder="com.example.app" value={app} onChange={(e) => setApp(e.target.value)} disabled={busy} style={{ minWidth: "14rem" }} />
      </div>
      <div className="form-field" style={{ flex: 1, minWidth: "16rem" }}>
        <label>Reason</label>
        <input placeholder="Accepted risk, false positive…" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} />
      </div>
      <button type="button" className="btn-primary" disabled={!canSubmit} onClick={() => onAdd(fp, app, reason)}>
        {busy ? "Adding…" : "Add baseline"}
      </button>
    </div>
  );
}
