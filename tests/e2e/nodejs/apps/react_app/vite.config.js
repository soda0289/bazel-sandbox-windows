import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Minimal, deterministic build: no content hashing / minification so the test
// can assert on stable output filenames, and emptyOutDir off so vite never
// tries to delete outside its own tree.
export default defineConfig({
  plugins: [react()],
  logLevel: "info",
  build: {
    minify: false,
    emptyOutDir: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
});
