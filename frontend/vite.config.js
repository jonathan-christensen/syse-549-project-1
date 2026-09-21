import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxies to the four services so the browser only ever talks to one origin
// and never trips CORS against the raw http.server-based backends (which
// don't implement OPTIONS preflight). Shared between `npm run dev` (hot
// reload, for active frontend work) and `npm run preview` (serves the
// `npm run build` output, for exercising it as it will actually run).
const proxy = {
  "/api/csp": {
    target: "http://127.0.0.1:4101",
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api\/csp/, ""),
  },
  "/api/verifier": {
    target: "http://127.0.0.1:4102",
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api\/verifier/, ""),
  },
  "/api/rp": {
    target: "http://127.0.0.1:4103",
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api\/rp/, ""),
  },
};

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 5173, proxy },
});
