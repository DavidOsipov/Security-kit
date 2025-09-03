import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";

import type * as dom from "../../src/dom";

describe("dom.ts remaining branches", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers();
  });

  afterEach(async () => {
    // cleanup any test overrides on the runtime module instance
    try {
      const m: any = await import("../../src/dom");
      try {
        (m.__test_sha256Hex as any).__test_importOverride = undefined;
      } catch {}
      try {
        (m.DOMValidator as any).__test_importOverride = undefined;
      } catch {}
      try {
        m.__test_resetDefaultValidatorForUnitTests();
      } catch {}
    } catch {
      /* ignore */
    }
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("sha256Hex: fast-sha256 function export path", async () => {
    // fast-sha256 exported directly as function; ensure earlier strategies are skipped
    const mod: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto") return Promise.resolve({});
      if (spec === "fast-sha256") {
        return Promise.resolve(
          (s: string) => s.split("").reverse().join("") + "f",
        );
      }
      return import(spec);
    };
    const savedCrypto = (globalThis as any).crypto;
    try {
      // ensure WebCrypto path not used in test env
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (globalThis as any).crypto;
      const out = await mod.__test_sha256Hex("abc");
      expect(out.endsWith("f")).toBe(true);
    } finally {
      (globalThis as any).crypto = savedCrypto;
      try {
        delete (mod.__test_sha256Hex as any).__test_importOverride;
      } catch {}
    }
  });

  it("sha256Hex: fast-sha256 object export with hashHex field", async () => {
    // fast-sha256 as object with hashHex; ensure node:crypto not used
    const mod2: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod2.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
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
      const out = await mod2.__test_sha256Hex("xyz");
      expect(out).toBe("h_xyz");
    } finally {
      (globalThis as any).crypto = savedCrypto;
      try {
        delete (mod2.__test_sha256Hex as any).__test_importOverride;
      } catch {}
    }
  });

  it("sha256Hex: hash-wasm sync sha256 export", async () => {
    // hash-wasm exposes sha256 synchronously; skip node:crypto and fast-sha256
    const mod3: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod3.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
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
      const out = await mod3.__test_sha256Hex("foo");
      expect(out).toBe("wasm_foo");
    } finally {
      (globalThis as any).crypto = savedCrypto;
      try {
        delete (mod3.__test_sha256Hex as any).__test_importOverride;
      } catch {}
    }
  });

  it("DOMValidator upgrade cache uses provided lru-cache default export", async () => {
    const seen: string[] = [];
    // Provide an LRU that records construction and has get/set
    const mod4: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod4.DOMValidator as any).__test_importOverride = (spec: string) => {
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

    const v = new mod4.DOMValidator();
    await v.__test_tryUpgradeCache();
    expect(seen).toContain("constructed");
  });

  it("background css-what parse failure emits validation_failure", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = (e) => {
      calls.push(e);
    };
    // Provide css-what that throws
    const mod5: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod5.DOMValidator as any).__test_importOverride = (spec: string) => {
      if (spec === "css-what") {
        return Promise.resolve({
          parse: (s: string) => {
            if (s.includes("__throw__")) throw new Error("bad");
            return [];
          },
        });
      }
      return import(spec);
    };
    const v = new mod5.DOMValidator({ auditHook } as any);
    // trigger background parse that will throw
    v.__test_backgroundCssWhatParse("selector__throw__");
    // wait a short bit for background async task
    try {
      await vi.runAllTimersAsync();
    } finally {
      // ensure timers are real again for other tests
      vi.useRealTimers();
    }
    // Expect at least one validation_failure event
    expect(calls.some((c) => c.kind === "validation_failure")).toBe(true);
  });

  it("emitValidationFailureEvent emits follow-up hash when enabled and sha256 works", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = async (e) => {
      calls.push(e);
    };

    // make sha256 succeed
    const mod6: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod6.__test_sha256Hex as any).__test_importOverride = (spec: string) => {
      if (spec === "node:crypto")
        return Promise.resolve({
          createHash: () => ({
            update: () => ({ digest: () => Buffer.from("deadbeef") }),
          }),
        });
      return import(spec);
    };
    const v = new mod6.DOMValidator({
      auditHook,
      emitSelectorHash: true,
    } as any);
    // call validateElement with invalid element to trigger emitValidationFailureEvent
    try {
      // this will throw and emit validation failure
      v.validateElement("not-an-element" as unknown);
    } catch {
      // expected
    }
    // Wait briefly for async hash follow-up
    try {
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }
    expect(calls.some((c) => c.kind === "validation_failure_hash")).toBe(true);
  });

  it("emitValidationFailureEvent handles sha256 failure (catch branch)", async () => {
    const calls: dom.AuditEvent[] = [];
    const auditHook: dom.AuditHook = async (e) => {
      calls.push(e);
    };
    // Make sha256 importer always reject so sha256Hex throws and triggers catch
    const mod7: any = await import("../../src/dom");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mod7.__test_sha256Hex as any).__test_importOverride = () =>
      Promise.reject(new Error("no crypto"));
    const v = new mod7.DOMValidator({
      auditHook,
      emitSelectorHash: true,
    } as any);
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
      try {
        await vi.runAllTimersAsync();
      } finally {
        vi.useRealTimers();
      }
    } finally {
      (globalThis as any).crypto = savedCrypto;
    }
    // Ensure base validation event emitted but follow-up hash not present
    expect(calls.some((c) => c.kind === "validation_failure")).toBe(true);
    expect(calls.some((c) => c.kind === "validation_failure_hash")).toBe(false);
  });

  it("containsWithinAllowedRoots true/false behaviors", async () => {
    // create elements in the document and test containment
    const root = document.createElement("div");
    root.id = "main-content";
    document.body.appendChild(root);
    const child = document.createElement("span");
    root.appendChild(child);

    const mod8: any = await import("../../src/dom");
    const v = new mod8.DOMValidator({} as any);
    expect(v.containsWithinAllowedRoots(child)).toBe(true);

    const orphan = document.createElement("p");
    expect(v.containsWithinAllowedRoots(orphan)).toBe(false);
  });

  it("safeCallAuditHook handles hook that throws and times out", async () => {
    const longHook = vi.fn(
      () =>
        new Promise((_, rej) => {
          vi.useFakeTimers();
          setTimeout(() => rej(new Error("boom")), 50);
        }),
    );
    const auditHook = (e: dom.AuditEvent) => longHook();
    const mod9: any = await import("../../src/dom");
    const v = new mod9.DOMValidator({
      auditHook,
      auditHookTimeoutMs: 10,
    } as any);
    // invoke safeCallAuditHook indirectly via invalidateCache audit
    v.invalidateCache();
    // allow time for hook to run and be caught
    await vi.runAllTimersAsync();
    expect(longHook).toHaveBeenCalled();
  });
});
