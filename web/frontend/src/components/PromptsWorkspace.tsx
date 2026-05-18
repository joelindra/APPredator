import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, apiPut } from "../api";
import { BusyOverlay, CheckSpinner } from "./CheckSpinner";
import { IconBot, IconPlus, IconRefresh } from "./Icons";

type AssetFile = { path: string; kind: string; group: string };

type Props = {
  isBusy: (k: string) => boolean;
  run: (k: string, fn: () => Promise<void>) => Promise<void>;
};

export function PromptsWorkspace({ isBusy, run }: Props) {
  const [files, setFiles] = useState<AssetFile[]>([]);
  const [selected, setSelected] = useState("");
  const [content, setContent] = useState("");
  const [loadedPath, setLoadedPath] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [showNewForm, setShowNewForm] = useState(false);
  const [newFolder, setNewFolder] = useState<"prompts" | "knowledge_base">("prompts");
  const [newBasename, setNewBasename] = useState("");
  const [newSubpath, setNewSubpath] = useState("");

  const loadFiles = useCallback(async () => {
    const r = (await apiGet("/api/config/assets/files")) as { files?: AssetFile[] };
    setFiles(Array.isArray(r.files) ? r.files : []);
  }, []);

  const loadContent = useCallback(
    async (path: string) => {
      if (!path) return;
      const r = (await apiGet(`/api/config/assets/content?path=${encodeURIComponent(path)}`)) as { content?: string };
      setContent(typeof r.content === "string" ? r.content : "");
      setLoadedPath(path);
      setDirty(false);
    },
    []
  );

  useEffect(() => {
    void run("promptsInit", async () => {
      await loadFiles();
    });
  }, [run, loadFiles]);

  useEffect(() => {
    if (!selected) return;
    void run("promptsLoad", async () => {
      await loadContent(selected);
    });
  }, [selected, run, loadContent]);

  const save = async () => {
    if (!selected || !loadedPath) return;
    await run("promptsSave", async () => {
      await apiPut("/api/config/assets/content", { path: selected, content });
      setDirty(false);
      await loadFiles();
    });
  };

  const createTxtFile = async () => {
    await run("promptsCreate", async () => {
      const r = (await apiPost("/api/config/assets/create-txt", {
        folder: newFolder,
        basename: newBasename,
        subpath: newSubpath,
      })) as { path?: string };
      const p = typeof r.path === "string" ? r.path : "";
      if (!p) throw new Error("Server did not return a path");
      await loadFiles();
      setSelected(p);
      setNewBasename("");
      setNewSubpath("");
      setShowNewForm(false);
    });
  };

  const busy =
    isBusy("promptsInit") || isBusy("promptsLoad") || isBusy("promptsSave") || isBusy("promptsCreate");

  return (
    <div className="prompts-workspace prompts-workspace__root">
      <BusyOverlay
        show={busy}
        text={isBusy("promptsSave") ? "Saving…" : isBusy("promptsCreate") ? "Creating…" : "Loading…"}
      />
      {isBusy("promptsInit") && !files.length && <CheckSpinner label="Indexing prompt files" />}
      <p className="prompts-workspace__lead">
        <IconBot size={16} aria-hidden /> Templates and knowledge files used as <strong>RAG</strong> context for scans. Pick a file, edit, then save — the next job uses the updated text.
      </p>
      <div className="prompts-workspace__grid">
        <aside className="prompts-workspace__sidebar">
          <div className="prompts-workspace__sidebar-head">
            <h3 className="prompts-workspace__title">
              <IconBot size={18} /> Library
            </h3>
            <div className="prompts-workspace__toolbar">
              <button
                type="button"
                className="btn-sm btn-primary"
                disabled={busy}
                onClick={() => setShowNewForm((v) => !v)}
                title={showNewForm ? "Close form" : "Create a new .txt file"}
              >
                <IconPlus size={14} aria-hidden />
                <span>New .txt</span>
              </button>
              <button type="button" className="btn-sm btn-ghost" disabled={busy} onClick={() => void run("promptsRefresh", loadFiles)} title="Reload list">
                <IconRefresh />
              </button>
            </div>
          </div>
          {showNewForm && (
            <div className="prompts-workspace__new-panel" role="region" aria-label="Create new text file">
              <p className="form-field-hint" style={{ margin: "0 0 0.65rem" }}>
                Creates a UTF-8 <code className="mono">.txt</code> only. Use letters, digits, <code className="mono">_</code>, and{" "}
                <code className="mono">-</code> in the name (good for notes or extra retrieval chunks).
              </p>
              <div className="prompts-workspace__new-fields">
                <label className="prompts-workspace__label" htmlFor="prompts-new-folder">
                  Folder
                </label>
                <select
                  id="prompts-new-folder"
                  className="prompts-workspace__select"
                  value={newFolder}
                  disabled={busy}
                  onChange={(e) => setNewFolder(e.target.value as "prompts" | "knowledge_base")}
                >
                  <option value="prompts">Prompt templates — config/prompts</option>
                  <option value="knowledge_base">Knowledge base — config/knowledge_base</option>
                </select>
                <label className="prompts-workspace__label" htmlFor="prompts-new-name">
                  File name
                </label>
                <div className="prompts-workspace__name-row">
                  <input
                    id="prompts-new-name"
                    type="text"
                    className="prompts-workspace__text-input mono"
                    placeholder="e.g. my_notes"
                    value={newBasename}
                    disabled={busy}
                    onChange={(e) => setNewBasename(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <span className="prompts-workspace__suffix" aria-hidden>
                    .txt
                  </span>
                </div>
                <label className="prompts-workspace__label" htmlFor="prompts-new-sub">
                  Subfolders <span className="prompts-workspace__optional">(optional)</span>
                </label>
                <input
                  id="prompts-new-sub"
                  type="text"
                  className="prompts-workspace__text-input mono"
                  placeholder="e.g. notes or custom_rules"
                  value={newSubpath}
                  disabled={busy}
                  onChange={(e) => setNewSubpath(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <div className="prompts-workspace__new-actions">
                <button type="button" className="btn-sm btn-ghost" disabled={busy} onClick={() => setShowNewForm(false)}>
                  Close
                </button>
                <button type="button" className="btn-sm btn-primary" disabled={busy || !newBasename.trim()} onClick={() => void createTxtFile()}>
                  Create file
                </button>
              </div>
            </div>
          )}
          <p className="hint" style={{ margin: "0 0 0.65rem", fontSize: "0.8rem" }}>
            YAML/JSON rules and mappings stay in place; this editor lists everything under{" "}
            <code className="mono">config/prompts</code> and <code className="mono">config/knowledge_base</code>.
          </p>
          <div className="prompts-workspace__list" role="listbox" aria-label="RAG configuration files">
            {files.map((f) => {
              const base = f.path.includes("/") ? f.path.slice(f.path.lastIndexOf("/") + 1) : f.path;
              return (
                <button
                  key={f.path}
                  type="button"
                  role="option"
                  aria-selected={selected === f.path}
                  className={`prompts-workspace__file${selected === f.path ? " active" : ""}`}
                  onClick={() => setSelected(f.path)}
                >
                  <div className="prompts-workspace__file-main">
                    <div style={{ minWidth: 0 }}>
                      <div className="prompts-workspace__file-title">{base}</div>
                      <div className="prompts-workspace__file-preview">{f.path}</div>
                    </div>
                    <span className="prompts-workspace__badge">{f.kind}</span>
                  </div>
                  <div className="prompts-workspace__file-actions">
                    <span className="muted" style={{ fontSize: "0.75rem" }}>
                      Open in editor
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </aside>
        <div className="prompts-workspace__editor">
          {!selected ? (
            <div className="empty-chart" style={{ minHeight: "200px" }}>
              Choose a file from the library to open the editor.
            </div>
          ) : (
            <>
              <div className="prompts-workspace__editor-bar">
                <code className="mono" style={{ color: "var(--text-primary)", fontSize: "0.88rem" }}>
                  {selected}
                </code>
                {dirty && <span className="badge badge-warn">Unsaved</span>}
                <div style={{ marginLeft: "auto", display: "flex", gap: "0.5rem" }}>
                  <button
                    type="button"
                    className="btn-ghost"
                    disabled={busy || !selected}
                    onClick={() => void run("promptsReloadOne", () => loadContent(selected))}
                  >
                    Revert
                  </button>
                  <button type="button" className="btn-primary" disabled={busy || !dirty} onClick={() => void save()}>
                    Save file
                  </button>
                </div>
              </div>
              <textarea
                className="prompts-workspace__textarea mono"
                spellCheck={false}
                value={content}
                onChange={(e) => {
                  setContent(e.target.value);
                  setDirty(true);
                }}
                disabled={busy}
                aria-label="File contents"
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
