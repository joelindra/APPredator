import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Keep in sync with scripts/start-api.mjs (APPREDATOR_API_PORT overrides both).
const apiPort = process.env.APPREDATOR_API_PORT || (process.platform === "win32" ? "8765" : "8080");
const apiOrigin = `http://127.0.0.1:${apiPort}`;

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: apiOrigin, changeOrigin: true, ws: true },
      "/docs": apiOrigin,
      "/openapi.json": apiOrigin,
    },
  },
});
