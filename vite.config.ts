import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import { readFileSync } from "fs";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };

// `QM_DEV_TARGET=https://<gateway> npm run dev` proxies the API + WebSocket to a live
// gateway so the UI can be developed against real telemetry.
const devTarget = process.env.QM_DEV_TARGET;

export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: devTarget
    ? {
        proxy: {
          "/api": { target: devTarget, changeOrigin: true, secure: false, ws: true },
        },
      }
    : undefined,
  build: {
    outDir: "dist",
    sourcemap: false,
    minify: "esbuild",
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (id.includes("lucide-react")) return "icons";
          if (
            id.includes("/react/") ||
            id.includes("/react-dom/") ||
            id.includes("/scheduler/") ||
            id.includes("/zustand/") ||
            id.includes("/@tanstack/react-query") ||
            id.includes("/@tanstack/query-core")
          ) {
            return "vendor";
          }
        },
      },
    },
  },
});
