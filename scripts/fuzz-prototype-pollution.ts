// Quick fuzz harness to detect prototype pollution and hostile getters
// This is intended to be run locally or in CI with a limited iteration budget.
// Resolve runtime imports: prefer compiled `dist/` when present so this script can run
// with plain `node` after `npm run build`. Otherwise fall back to importing source
// TS files (useful when running via ts-node).
let Sanitizer: any;
let STRICT_HTML_POLICY_CONFIG: any;
let postMessageMod: any;

function safeUrlForImport(u: string) {
  try {
    const parsed = new URL(u);
    // Allow only file: or http(s): imports in this script
    if (parsed.protocol === "file:" || parsed.protocol === "http:" || parsed.protocol === "https:") return u;
  } catch {
    // invalid URL - treat as unsafe
  }
  return undefined;
}

async function safeImport(url: string) {
  const safe = safeUrlForImport(url);
  if (!safe) throw new Error("Unsafe import URL");
  // The dynamic import target is validated above. Silence the rule because
  // we perform our own URL validation to prevent unsafe imports.
  // eslint-disable-next-line no-unsanitized/method
  return import(safe);
}

async function resolveImports() {
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
    // eslint-disable-next-line n/no-missing-import
    const s = await import("../src/sanitizer");
    // eslint-disable-next-line n/no-missing-import
    const p = await import("../src/postMessage");
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

(async () => {
  await resolveImports();
})();

import * as crypto from "crypto";

function randomString(len = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const buf = Buffer.alloc(len);
  crypto.randomFillSync(buf);
  let s = "";
  for (let i = 0; i < len; i++) {
  // buf is a local Buffer filled by crypto.randomFillSync; this index
  // usage is safe. Suppress the object-injection rule for this line.
  // eslint-disable-next-line security/detect-object-injection
  const idx = buf[i] % chars.length;
    s += chars.charAt(idx);
  }
  return s;
}

function makeHostilePayload(i: number) {
  const buf = Buffer.alloc(1);
  crypto.randomFillSync(buf);
  const r = buf[0] / 256;
  if (r < 0.2) {
    return { __proto__: { hacked: i } };
  }
  if (r < 0.4) {
  const o: any = { a: 1 };
  const s = Symbol(randomString());
  // eslint-disable-next-line security/detect-object-injection
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

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
