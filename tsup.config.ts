import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  outDir: "dist",
  // Do not bundle optional dependencies (they are optional fallbacks).
  // This keeps the runtime small and allows consumers to opt-in by
  // installing the optional packages when needed.
  external: [
    "hash-wasm",
    "fast-sha256",
    "css-what",
    "lru-cache",
    "isomorphic-dompurify",
    "dompurify"
  ],
  // Note: do not minify here; consumers and bundlers (webpack/rollup/esbuild) will
  // perform production minification and tree-shaking. We only externalize
  // optional deps to avoid bundling large fallback runtimes.
  // Ensure modern extensions: .mjs for esm, .cjs for cjs
  outExtension({ format }) {
    if (format === "cjs") return { js: ".cjs" };
    if (format === "esm") return { js: ".mjs" };
    return { js: ".js" };
  },
});
