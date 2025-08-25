// Quick fuzz harness to detect prototype pollution and hostile getters
// This is intended to be run locally or in CI with a limited iteration budget.
// Resolve runtime imports: prefer compiled `dist/` when present so this script can run
// with plain `node` after `npm run build`. Otherwise fall back to importing source
// TS files (useful when running via ts-node).
let Sanitizer: any;
let STRICT_HTML_POLICY_CONFIG: any;
let postMessageMod: any;

import { fileURLToPath } from "node:url";

async function resolveImports() {
  // First try to import from compiled dist/ using a computed file URL so bundlers
  // won't try to resolve the path at build-time.
  try {
    const distUrl = new URL("../dist/index.mjs", import.meta.url).href;
    const d = await import(distUrl);
    Sanitizer = d.Sanitizer ?? d.default?.Sanitizer;
    STRICT_HTML_POLICY_CONFIG = d.STRICT_HTML_POLICY_CONFIG ?? d.default?.STRICT_HTML_POLICY_CONFIG;
    try {
      const pmUrl = new URL("../dist/scripts/fuzz-prototype-pollution.mjs", import.meta.url).href.replace("fuzz-prototype-pollution.mjs", "src/postMessage.mjs");
      postMessageMod = await import(pmUrl);
    } catch (e) {
      postMessageMod = d.postMessage ?? d.default?.postMessage ?? {};
    }
    return;
  } catch (e) {
    // fall through to source imports
  }

  // Fallback to source TypeScript imports (this works when running via ts-node).
  const s = await import("../src/sanitizer");
  const p = await import("../src/postMessage");
  Sanitizer = s.Sanitizer;
  STRICT_HTML_POLICY_CONFIG = s.STRICT_HTML_POLICY_CONFIG;
  postMessageMod = p;
}

(async () => {
  await resolveImports();
})();

function randomString(len = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function makeHostilePayload(i: number) {
  const r = Math.random();
  if (r < 0.2) {
    return { __proto__: { hacked: i } };
  }
  if (r < 0.4) {
    const o: any = { a: 1 };
    const s = Symbol(randomString());
    o[s] = { evil: i };
    return o;
  }
  if (r < 0.6) {
    const o: any = { a: 1 };
    Object.defineProperty(o, "b", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
    });
    return o;
  }
  if (r < 0.8) {
    const o: any = { nested: {} };
    o.nested.deep = { __proto__: { p: i } };
    return o;
  }
  // circular
  const a: any = { x: 1 };
  a.self = a;
  return a;
}

async function main() {
  const dp: any = { sanitize: (s: string) => s };
  const sanitizer = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });

  for (let i = 0; i < 100; i++) {
    const before = Object.prototype.hasOwnProperty("hacked");
    const p = makeHostilePayload(i);
    try {
      // run through sanitizer
      try {
        sanitizer.getSanitizedString(JSON.stringify(p), "strict");
      } catch {}
      // run through postMessage validator
      try {
        postMessageMod._validatePayload?.(p, (d: any) => true as any);
      } catch {}
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

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
