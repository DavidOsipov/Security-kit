import { describe, it, expect, vi, afterEach } from "vitest";

import * as dom from "../../src/dom";

describe("dom.ts remaining branches", () => {
  afterEach(() => {
    // cleanup any test overrides
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = undefined;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.DOMValidator as any).__test_importOverride = undefined;
    dom.__test_resetDefaultValidatorForUnitTests();
    vi.restoreAllMocks();
  });

  it("sha256Hex: fast-sha256 function export path", async () => {
    // fast-sha256 exported directly as function; ensure earlier strategies are skipped
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto") return Promise.resolve({});
      if (spec === "fast-sha256") {
        return Promise.resolve((s: string) => s.split("").reverse().join("") + "f");
      }
      return import(spec);
    };
    const savedCrypto = (globalThis as any).crypto;
    try {
      // ensure WebCrypto path not used in test env
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (globalThis as any).crypto;
      const out = await dom.__test_sha256Hex("abc");
      expect(out.endsWith("f")).toBe(true);
    } finally {
      (globalThis as any).crypto = savedCrypto;
    }
  });

  it("sha256Hex: fast-sha256 object export with hashHex field", async () => {
    // fast-sha256 as object with hashHex; ensure node:crypto not used
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto") return Promise.resolve({});
      if (spec === "fast-sha256") {
        return Promise.resolve({ hashHex: (s: string) => `h_${s}` });
      }
      return import(spec);
    };
    const savedCrypto = (globalThis as any).crypto;
    try {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (globalThis as any).crypto;
      const out = await dom.__test_sha256Hex("xyz");
      expect(out).toBe("h_xyz");
    } finally {
      (globalThis as any).crypto = savedCrypto;
    }
  });

  it("sha256Hex: hash-wasm sync sha256 export", async () => {
    // hash-wasm exposes sha256 synchronously; skip node:crypto and fast-sha256
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto") return Promise.resolve({});
      if (spec === "fast-sha256") return Promise.resolve({});
      if (spec === "hash-wasm") {
        return Promise.resolve({ sha256: (s: string) => `wasm_${s}` });
      }
      return import(spec);
    };
    const savedCrypto = (globalThis as any).crypto;
    try {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (globalThis as any).crypto;
      const out = await dom.__test_sha256Hex("foo");
      expect(out).toBe("wasm_foo");
    } finally {
      (globalThis as any).crypto = savedCrypto;
    }
  });

  it("DOMValidator upgrade cache uses provided lru-cache default export", async () => {
    const seen: string[] = [];
    // Provide an LRU that records construction and has get/set
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.DOMValidator as any).__test_importOverride = (spec: string) => {
      if (spec === "lru-cache") {
        class LRU {
          _map = new Map();
          constructor(opts: any) {
            seen.push("constructed");
          }
          get(k: string) {
            return this._map.get(k);
          }
          set(k: string, v: any) {
            this._map.set(k, v);
          }
        }
        return Promise.resolve({ default: LRU });
      }
      return import(spec);
    };

    const v = new dom.DOMValidator();
    await v.__test_tryUpgradeCache();
    expect(seen).toContain("constructed");
  });

  it("background css-what parse failure emits validation_failure", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = (e) => {
      calls.push(e);
    };
    // Provide css-what that throws
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.DOMValidator as any).__test_importOverride = (spec: string) => {
      if (spec === "css-what") {
        return Promise.resolve({ parse: (s: string) => { if (s.includes("__throw__")) throw new Error("bad"); return []; } });
      }
      return import(spec);
    };
  const v = new dom.DOMValidator({ auditHook } as any);
    // trigger background parse that will throw
    v.__test_backgroundCssWhatParse("selector__throw__");
    // wait a short bit for background async task
    await new Promise((res) => setTimeout(res, 200));
    // Expect at least one validation_failure event
    expect(calls.some((c) => c.kind === "validation_failure")).toBe(true);
  });

  it("emitValidationFailureEvent emits follow-up hash when enabled and sha256 works", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = async (e) => {
      calls.push(e);
    };

    // make sha256 succeed
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto") return Promise.resolve({ createHash: () => ({ update: () => ({ digest: () => Buffer.from("deadbeef") }) }) });
      return import(spec);
    };

    const v = new dom.DOMValidator({ auditHook, emitSelectorHash: true } as any);
    // call validateElement with invalid element to trigger emitValidationFailureEvent
    try {
      // this will throw and emit validation failure
      v.validateElement("not-an-element" as unknown);
    } catch {
      // expected
    }
    // Wait briefly for async hash follow-up
    await new Promise((res) => setTimeout(res, 300));
    expect(calls.some((c) => c.kind === "validation_failure_hash")).toBe(true);
  });

  it("emitValidationFailureEvent handles sha256 failure (catch branch)", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = async (e) => {
      calls.push(e);
    };
    // Make sha256 importer always reject so sha256Hex throws and triggers catch
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dom.__test_sha256Hex as any).__test_importOverride = () =>
      Promise.reject(new Error("no crypto"));

    const v = new dom.DOMValidator({ auditHook, emitSelectorHash: true } as any);
    const savedCrypto = (globalThis as any).crypto;
    try {
      // disable WebCrypto path so sha256 fails
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (globalThis as any).crypto;
      try {
        v.validateElement("nope" as unknown);
      } catch {
        // expected
      }
      await new Promise((r) => setTimeout(r, 300));
    } finally {
      (globalThis as any).crypto = savedCrypto;
    }
    // Ensure base validation event emitted but follow-up hash not present
    expect(calls.some((c) => c.kind === "validation_failure")).toBe(true);
    expect(calls.some((c) => c.kind === "validation_failure_hash")).toBe(false);
  });

  it("containsWithinAllowedRoots true/false behaviors", () => {
    // create elements in the document and test containment
    const root = document.createElement("div");
    root.id = "main-content";
    document.body.appendChild(root);
    const child = document.createElement("span");
    root.appendChild(child);

    const v = new dom.DOMValidator({} as any);
    expect(v.containsWithinAllowedRoots(child)).toBe(true);

    const orphan = document.createElement("p");
    expect(v.containsWithinAllowedRoots(orphan)).toBe(false);
  });

  it("safeCallAuditHook handles hook that throws and times out", async () => {
    const longHook = vi.fn(() => new Promise((_, rej) => setTimeout(() => rej(new Error("boom")), 50)));
    const auditHook = (e: dom.AuditEvent) => longHook();
  const v = new dom.DOMValidator({ auditHook, auditHookTimeoutMs: 10 } as any);
    // invoke safeCallAuditHook indirectly via invalidateCache audit
    v.invalidateCache();
    // allow time for hook to run and be caught
    await new Promise((res) => setTimeout(res, 100));
    expect(longHook).toHaveBeenCalled();
  });
});
