/**
 * Start FastAPI (uvicorn) from repo root using the `python` on PATH.
 * Override interpreter: APPREDATOR_PYTHON=python3 (or full path to python.exe).
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const python = process.env.APPREDATOR_PYTHON?.trim() || "python";

// Windows often returns WinError 10013 on 8080 (Hyper-V / excluded port ranges or conflicts).
const defaultPort = process.platform === "win32" ? "8765" : "8080";
const port = process.env.APPREDATOR_API_PORT || defaultPort;

// Uvicorn --reload starts a multiprocessing spawn child; Ctrl+C during long Apktool/JADX often prints a
// noisy KeyboardInterrupt traceback from threading._shutdown in that child. Default: no --reload.
// Opt in to hot reload: APPREDATOR_API_RELOAD=1
const useReload = process.env.APPREDATOR_API_RELOAD === "1";

// When stdout is not a TTY (e.g. npm/concurrently → Node spawn), Python uses block-buffered
// stdout and Loguru lines appear late or only after the request ends. -u + PYTHONUNBUFFERED fixes that.
const childEnv = { ...process.env, PYTHONUNBUFFERED: "1" };
const uvicornArgs = [
  "-u",
  "-m",
  "uvicorn",
  "web.backend.main:app",
  ...(useReload ? ["--reload"] : []),
  "--host",
  "127.0.0.1",
  "--port",
  port,
];
const proc = spawn(
  python,
  uvicornArgs,
  { cwd: root, stdio: "inherit", shell: false, env: childEnv }
);

/** Treat interrupt-style exits as success so dev shutdown is not a false "crash". */
function normalizeChildExit(code, signal) {
  if (signal === "SIGINT" || signal === "SIGTERM") return 0;
  if (code === 0) return 0;
  // Windows: STATUS_CONTROL_C_EXIT (0xC000013A) — Ctrl+C / console stop
  if (code === 3221225786 || code === -1073741510) return 0;
  // Unix: 128 + SIGINT, or generic interrupt
  if (code === 130 || code === 2) return 0;
  return code ?? 1;
}

let childExited = false;
proc.on("exit", (code, signal) => {
  childExited = true;
  process.exit(normalizeChildExit(code, signal));
});

function forwardSignalToChild(sig) {
  if (childExited) return;
  try {
    proc.kill(sig);
  } catch {
    try {
      proc.kill();
    } catch {
      /* ignore */
    }
  }
}
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => forwardSignalToChild(sig));
}
