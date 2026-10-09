import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

// The vendored bundle reports the exact upstream version it was built from, so the SPA (and the
// tests) can tell a stale artifact from a fresh one without trusting a comment.
const crepe = JSON.parse(
  readFileSync(fileURLToPath(new URL("./node_modules/@milkdown/crepe/package.json", import.meta.url)), "utf8")
);

export default defineConfig({
  define: {
    __MILKDOWN_VERSION__: JSON.stringify(crepe.version),
    __BUILT_AT__: JSON.stringify(new Date().toISOString().slice(0, 10)),
    // Lib builds do not get Vite's usual `process.env.NODE_ENV` replacement, and parts of the
    // Crepe/Vue stack read it at module scope — without this the bundle throws
    // «process is not defined» the moment it is imported.
    "process.env.NODE_ENV": JSON.stringify("production"),
    "process.env": "{}"
  },
  resolve: {
    // Crepe's code-block feature pulls every grammar CodeMirror ships (~120 chunks, ~1.5 MB). The
    // vault only needs the few its notes use — see src/language-data.stub.js.
    alias: {
      "@codemirror/language-data": fileURLToPath(new URL("./src/language-data.stub.js", import.meta.url))
    }
  },
  build: {
    target: "es2020",
    minify: "esbuild",
    outDir: "dist",
    emptyOutDir: true,
    cssCodeSplit: false,
    // One file, no chunks: the server serves static assets from a fixed allow-list, so a bundle
    // that fans out into a hundred hashed files would be a hundred more entries to keep in sync.
    rollupOptions: { output: { inlineDynamicImports: true } },
    lib: {
      entry: "src/entry.js",
      formats: ["es"],
      fileName: () => "milkdown-editor.js"
    }
  }
});
