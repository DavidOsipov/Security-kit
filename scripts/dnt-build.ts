#!/usr/bin/env -S deno run -A
// Deno-first npm build using @deno/dnt
// Hardened, minimal, and reproducible. Generates npm/ directory ready to publish.

/*
 SPDX-License-Identifier: LGPL-3.0-or-later
 SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
*/

import { build, emptyDir } from "jsr:@deno/dnt@^0.41.3";

// Global type declarations for dnt build environment
declare global {
  var __TEST__: boolean | undefined;
  interface Window {
    trustedTypes?: {
      createPolicy: (name: string, rules: any) => any;
    };
  }
  interface GlobalThis {
    trustedTypes?: {
      createPolicy: (name: string, rules: any) => any;
    };
  }
}

// Small helper to read JSON safely (repository-local)
async function readJson<T = unknown>(path: string): Promise<T> {
  const txt = await Deno.readTextFile(path);
  return JSON.parse(txt) as T;
}

type Pkg = {
  name: string;
  version: string;
  description?: string;
  license?: string;
  repository?: { type?: string; url?: string } | string;
  homepage?: string;
  bugs?: { url?: string } | string;
  keywords?: string[];
  author?: string;
  engines?: { node?: string };
  publishConfig?: { access?: string };
};

const ROOT = new URL("../", import.meta.url);
const OUT_DIR = new URL("../npm/", import.meta.url);

console.log("🏗️  Starting Deno dnt build...");

// Clean output
await emptyDir(OUT_DIR);

const pkg = await readJson<Pkg>(new URL("../package.json", import.meta.url).pathname);

// Build using dnt
await build({
  entryPoints: [
    // Public API root
    { kind: "export", name: ".", path: "./src/index.ts" },
    // Test helpers (exported for consumers' tests as in current package)
    { kind: "export", name: "./test-internals", path: "./tests/helpers/test-internals.ts" },
    // Worker and server subpath exports
    { kind: "export", name: "./worker", path: "./src/worker/signing-worker.ts" },
    { kind: "export", name: "./server", path: "./server/verify-api-request-signature.ts" },
    { kind: "export", name: "./server/nonce-store", path: "./server/nonce-store.ts" },
    { kind: "export", name: "./server/redis-nonce-store", path: "./server/redis-nonce-store.ts" },
  ],
  outDir: OUT_DIR.pathname,
  // Avoid unnecessary shims; this library targets modern platforms
  shims: {
    deno: false,
    custom: []
  },
  typeCheck: "both",
  test: false,
  compilerOptions: {
    // Align with repo TS strictness  
    lib: ["ES2022", "DOM"],
    target: "ES2022",
    // Skip lib checking for faster builds while maintaining security
    skipLibCheck: true,
    // Keep JSX defaults off; not used here
  },
  // Define compile-time globals for security-compliant production builds
  globalAwaitSupport: false,
  scriptModule: false,
  package: {
    name: pkg.name,
    version: pkg.version,
    description: pkg.description,
    license: pkg.license ?? "LGPL-3.0-or-later",
    repository: typeof pkg.repository === 'string' 
      ? { type: 'git', url: pkg.repository }
      : pkg.repository ? { 
          type: pkg.repository.type ?? 'git',
          url: pkg.repository.url ?? ''
        } : undefined,
    homepage: pkg.homepage,
    bugs: typeof pkg.bugs === 'string'
      ? { url: pkg.bugs }
      : pkg.bugs,
    keywords: pkg.keywords,
    author: pkg.author,
    type: "module",
    sideEffects: false,
    engines: pkg.engines ?? { node: ">=18.18.0" },
    publishConfig: pkg.publishConfig ?? { access: "public" },
    // dnt will generate proper exports/types mapping for each entryPoint
    // but we also include explicit files to publish and SBOM artifacts if present
    files: [
      "esm/",
      "script/",
      "types/",
      "package.json",
      "README.md",
      "LICENSE",
      "sbom.json",
      "sbom.spdx.json"
    ],
  },
  mappings: {
    // Ensure node: specifiers remain intact for Node environments.
    // dnt handles these by default; explicit mapping left empty intentionally.
  },
  // After build, copy meta files
  postBuild: async () => {
    console.log("📋 Running post-build steps...");
    
    const copy = async (rel: string) => {
      const src = new URL(rel, ROOT);
      const dst = new URL(rel, OUT_DIR);
      try {
        await Deno.copyFile(src, dst);
        console.log(`📄 Copied ${rel}`);
      } catch {
        // optional files may not exist; ignore
        console.log(`⚠️  Skipped ${rel} (not found)`);
      }
    };
    
    await copy("README.md");
    await copy("LICENSE");
    // If SBOMs exist in root, include them in the publish dir as artifacts
    await copy("sbom.json");
    await copy("sbom.spdx.json");
    
    console.log("✅ Post-build complete: metadata files copied");
  }
});

console.log("✅ dnt build complete: npm/ ready to publish");
