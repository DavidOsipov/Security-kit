import { defineConfig } from "tsup";

export default defineConfig([
  // Main entry point
  {
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
      "dompurify",
    ],
    // Disable code splitting to keep modules intact for tree-shaking
    splitting: false,
    // Note: do not minify here; consumers and bundlers (webpack/rollup/esbuild) will
    // perform production minification and tree-shaking. We only externalize
    // optional deps to avoid bundling large fallback runtimes.
    // Ensure modern extensions: .mjs for esm, .cjs for cjs
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      if (format === "esm") return { js: ".mjs" };
      return { js: ".js" };
    },
  },
  // Worker module (for browser environments)
  {
    entry: ["src/worker/signing-worker.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    outDir: "dist/worker",
    // Disable code splitting to keep worker as a single file
    splitting: false,
    external: [
      "hash-wasm",
      "fast-sha256",
      "css-what",
      "lru-cache",
      "isomorphic-dompurify",
      "dompurify",
    ],
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      if (format === "esm") return { js: ".mjs" };
      return { js: ".js" };
    },
  },
  // Server modules (for Node.js environments)
  {
    entry: [
      "server/nonce-store.ts",
      "server/redis-nonce-store.ts",
      "server/verify-api-request-signature.ts",
    ],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    outDir: "dist/server",
    // Disable code splitting to prevent chunk files and keep modules separate
    splitting: false,
    external: [
      "hash-wasm",
      "fast-sha256",
      "css-what",
      "lru-cache",
      "isomorphic-dompurify",
      "dompurify",
      "redis", // Redis is an external dependency for server modules
    ],
    outExtension({ format }) {
      if (format === "cjs") return { js: ".cjs" };
      if (format === "esm") return { js: ".mjs" };
      return { js: ".js" };
    },
  },
]);
