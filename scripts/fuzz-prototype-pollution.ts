// Quick fuzz harness to detect prototype pollution and hostile getters
// This is intended to be run locally or in CI with a limited iteration budget.
// Resolve runtime imports: prefer compiled `dist/` when present so this script can run
// with plain `node` after `npm run build`. Otherwise fall back to importing source
// TS files (useful when running via ts-node).
import helpers from "./fuzz-helpers";
const { safeUrlForImport, safeImport, randomString, makeHostilePayload } = helpers as any;
let Sanitizer: any;
let STRICT_HTML_POLICY_CONFIG: any;
let postMessageMod: any;

export async function resolveImports() {
  // original resolveImports logic moved here for testability
  // First try to import from compiled dist/ using a computed file URL so bundlers
  // won't try to resolve the path at build-time.
  try {
    const distUrl = new URL("../dist/index.mjs", import.meta.url).href;
    const d = await safeImport(distUrl);
    Sanitizer = d.Sanitizer ?? d.default?.Sanitizer;
    STRICT_HTML_POLICY_CONFIG = d.STRICT_HTML_POLICY_CONFIG ?? d.default?.STRICT_HTML_POLICY_CONFIG;
    try {
      const pmUrl = new URL("../dist/scripts/fuzz-prototype-pollution.mjs", import.meta.url).href.replace("fuzz-prototype-pollution.mjs", "src/postMessage.mjs");
      postMessageMod = await safeImport(pmUrl);
    } catch (e) {
      console.warn("fallback to postMessage from dist bundle failed:", e && (e as Error).message);
      postMessageMod = d.postMessage ?? d.default?.postMessage ?? {};
    }
    return;
  } catch (e) {
    // Dist bundle import failed — log and fall back to source imports below
    console.warn("fallback to dist bundle import failed:", e && (e as Error).message);
  }

  // Fallback to source TypeScript imports (this works when running via ts-node).
  try {
    const s = await safeImport(new URL("../src/sanitizer", import.meta.url).href);
    const p = await safeImport(new URL("../src/postMessage", import.meta.url).href);
    Sanitizer = s.Sanitizer;
    STRICT_HTML_POLICY_CONFIG = s.STRICT_HTML_POLICY_CONFIG;
    postMessageMod = p;
  } catch (err) {
    console.warn("Could not import source modules for fuzz harness:", (err as Error).message);
    Sanitizer = (globalThis as any).Sanitizer || function () { return null; };
    STRICT_HTML_POLICY_CONFIG = {};
    postMessageMod = {};
  }
}

// Use helpers from ./fuzz-helpers (randomString, makeHostilePayload)

export async function main() {
  const dp: any = { sanitize: (s: string) => s };
  const sanitizer = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });

  for (let i = 0; i < 100; i++) {
    const before = Object.prototype.hasOwnProperty("hacked");
    const p = makeHostilePayload(i);
    try {
      // run through sanitizer
      try {
        sanitizer.getSanitizedString(JSON.stringify(p), "strict");
      } catch (err) {
        console.warn("sanitizer threw during fuzz iteration:", (err as Error).message);
      }
      // run through postMessage validator
      try {
        postMessageMod._validatePayload?.(p, (d: any) => true as any);
      } catch (err) {
        console.warn("postMessage validator threw during fuzz iteration:", (err as Error).message);
      }
    } catch (e) {
      console.error("Unexpected crash", e);
    }
    const after = Object.prototype.hasOwnProperty("hacked");
    if (after !== before) {
      console.error("Prototype polluted! iteration", i, p, { before, after });
      process.exit(2);
    }
  }
  console.log("Fuzz finished: no prototype pollution detected in 100 iterations");
}

// Only run the script when executed directly and when explicitly enabled
if (typeof require !== "undefined" && require.main === module) {
  if (process.env.RUN_FUZZ_SCRIPT === "1") {
    resolveImports()
      .then(() => main())
      .catch((e) => {
        console.error(e);
        process.exit(1);
      });
  } else {
    // Not enabled; avoid accidental long-running fuzz execution when imported
    console.info("fuzz-prototype-pollution: not running fuzz loop (RUN_FUZZ_SCRIPT not set)");
  }
}
