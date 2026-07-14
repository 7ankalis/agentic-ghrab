import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// The SPA talks to the FastAPI backend on :8000. In dev we proxy /api so the
// browser sees a single origin (no CORS preflight surprises).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VOC_API_URL || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
