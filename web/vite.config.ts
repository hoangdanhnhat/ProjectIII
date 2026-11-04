/// <reference types="vitest/config" />
import { fileURLToPath } from "node:url";
import { mkdirSync, writeFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are embedded into the Go server via //go:embed, so they are
// written straight into internal/webui/dist. During the migration the
// console is served at /next/; flip the base to "/" at cutover.
const outDir = fileURLToPath(new URL("../internal/webui/dist", import.meta.url));

export default defineConfig({
  base: "/next/",
  plugins: [
    react(),
    {
      // Re-create the marker file after every build so the committed
      // internal/webui/dist/.embed stays in the tree (go:embed needs the
      // directory to exist even before a frontend build has run).
      name: "keep-embed-marker",
      closeBundle() {
        mkdirSync(outDir, { recursive: true });
        writeFileSync(`${outDir}/.embed`, "");
      },
    },
  ],
  build: {
    outDir,
    emptyOutDir: true,
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/v1": {
        target: process.env.VITE_API_PROXY || "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
