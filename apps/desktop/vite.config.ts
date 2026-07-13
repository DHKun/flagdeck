import { resolve } from "node:path";

import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  plugins: [svelte()],
  server: {
    host: "127.0.0.1",
    port: 14200,
    strictPort: true,
  },
  build: {
    target: "es2022",
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        probe: resolve(import.meta.dirname, "probe.html"),
      },
    },
  },
});
