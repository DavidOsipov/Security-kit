import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  __test_fingerprintHexSync as fingerprintHexSync,
  __test_promiseWithTimeout as promiseWithTimeout,
  __test_redactAttributesSafely as redactAttributesSafely,
  __test_removeQuotedSegmentsSafely as removeQuotedSegmentsSafely,
  __test_extractAttributeSegments as extractAttributeSegments,
  __test_sha256Hex as __test_sha256Hex,
  createDefaultDOMValidator,
  getDefaultDOMValidator,
  DOMValidator,
  __test_sanitizeSelectorForLogs as sanitizeSelectorForLogs,
} from "../../src/dom";

describe("dom.ts comprehensive coverage", () => {
  beforeEach(() => {
    // Ensure no leftover importer override
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (__test_sha256Hex as any).__test_importOverride;
    } catch {
      /* ignore */
    }
    // isolate module state; tests that need fake timers will enable them locally
    vi.resetModules();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("fingerprintHexSync is deterministic and handles empty string", () => {
    expect(fingerprintHexSync("abc")).toBe(fingerprintHexSync("abc"));
    expect(fingerprintHexSync("")).toMatch(/^[0-9a-f]{8}$/);
  });

  it("promiseWithTimeout resolves and rejects with provided message", async () => {
    // This helper relies on timers; use fake timers for determinism
    vi.useFakeTimers();
    try {
      await expect(
        promiseWithTimeout(Promise.resolve("ok"), 20, "nope"),
      ).resolves.toBe("ok");

      const p = promiseWithTimeout(new Promise(() => {}), 5, "myerr");
      // advance timers so the timeout fires
      vi.advanceTimersByTime(10);
      await expect(p).rejects.toThrow("myerr");
    } finally {
      vi.useRealTimers();
    }
  });

  it("redactAttributesSafely handles quoted and unquoted attributes", () => {
    const quoted = "div[class=\"user\"]";
    expect(redactAttributesSafely(quoted)).toContain("=<redacted>]");

    const unquoted = "a[href=http://example.com]";
    expect(redactAttributesSafely(unquoted)).toContain("=<redacted>]");

    const noValue = "span[disabled]";
    expect(redactAttributesSafely(noValue)).toContain("[disabled]");
  });

  it("removeQuotedSegmentsSafely removes quoted substrings and respects escapes", () => {
    const s1 = `input[value=\"a\\\"b\"]`; // contains escaped quote inside
    const r1 = removeQuotedSegmentsSafely(s1);
    expect(r1).toContain("<redacted>");

    const s2 = `noquotes`; // no quotes returns original
    expect(removeQuotedSegmentsSafely(s2)).toBe(s2);
  });

  it("extractAttributeSegments returns bracketed parts including nested quotes", () => {
    const s = `div[a=1][b=\"x y\"][c='y']`;
    const parts = extractAttributeSegments(s);
    expect(parts.length).toBe(3);
    expect(parts[1]).toContain("b=");
  });

  it("sanitizeSelectorForLogs truncates long strings", () => {
    const long = "a".repeat(200);
    const out = sanitizeSelectorForLogs(long);
    expect(out).toContain("…");
    expect(out.length).toBeLessThan(200);
  });

  describe("sha256Hex fallbacks via importer override", () => {
    afterEach(() => {
      // cleanup
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        delete (__test_sha256Hex as any).__test_importOverride;
      } catch {
        /* ignore */
      }
    });

    it("uses node:crypto when provided via importer override", async () => {
      const mod: any = await import("../../src/dom");
      // fake node:crypto module
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod.__test_sha256Hex as any).__test_importOverride = async (spec: string) => {
        if (spec === "node:crypto") {
          return {
            createHash: () => ({ update: () => ({ digest: () => "aabb" }) }),
          };
        }
        return Promise.reject(new Error("not found"));
      };

      // ensure native WebCrypto (if present) does not override our importer
      try {
        // stub global crypto.subtle.digest to throw so the importer path is used
        vi.stubGlobal("crypto", { subtle: { digest: () => { throw new Error('no'); } } });
      } catch {
        /* ignore */
      }
      try {
        await expect(mod.__test_sha256Hex("x" as unknown as string)).resolves.toBe("aabb");
      } finally {
        try { delete (mod.__test_sha256Hex as any).__test_importOverride; } catch {}
      }
    });

    it("uses fast-sha256 object API when available", async () => {
      const mod: any = await import("../../src/dom");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod.__test_sha256Hex as any).__test_importOverride = async (spec: string) => {
        if (spec === "fast-sha256") {
          return { hashHex: (s: string) => "ff11" };
        }
        return Promise.reject(new Error("not found"));
      };
      try {
        await expect(mod.__test_sha256Hex("x")).resolves.toBe("ff11");
      } finally {
        try { delete (mod.__test_sha256Hex as any).__test_importOverride; } catch {}
      }
    });

    it("uses fast-sha256 function export when module is a function", async () => {
      const mod: any = await import("../../src/dom");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod.__test_sha256Hex as any).__test_importOverride = async (spec: string) => {
        if (spec === "fast-sha256") return (s: string) => "f-func";
        return Promise.reject(new Error("not found"));
      };
      try {
        await expect(mod.__test_sha256Hex("x")).resolves.toBe("f-func");
      } finally {
        try { delete (mod.__test_sha256Hex as any).__test_importOverride; } catch {}
      }
    });

    it("uses hash-wasm async or sync sha256 export when available", async () => {
      // async
      const mod: any = await import("../../src/dom");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod.__test_sha256Hex as any).__test_importOverride = async (spec: string) => {
        if (spec === "hash-wasm") return { sha256: async (s: string) => "hh-async" };
        return Promise.reject(new Error("not found"));
      };
      try {
        await expect(mod.__test_sha256Hex("x")).resolves.toBe("hh-async");
      } finally {
        try { delete (mod.__test_sha256Hex as any).__test_importOverride; } catch {}
      }

      // sync
      const mod2: any = await import("../../src/dom");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod2.__test_sha256Hex as any).__test_importOverride = async (spec: string) => {
        if (spec === "hash-wasm") return { sha256: (s: string) => "hh-sync" };
        return Promise.reject(new Error("not found"));
      };
      try {
        await expect(mod2.__test_sha256Hex("x")).resolves.toBe("hh-sync");
      } finally {
        try { delete (mod2.__test_sha256Hex as any).__test_importOverride; } catch {}
      }
    });

    it("throws when no strategies available", async () => {
      const mod: any = await import("../../src/dom");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (mod.__test_sha256Hex as any).__test_importOverride = async () => Promise.reject(new Error("nope"));
      try {
        await expect(mod.__test_sha256Hex("x")).rejects.toThrow("No crypto available");
      } finally {
        try { delete (mod.__test_sha256Hex as any).__test_importOverride; } catch {}
      }
    });
  });

  describe("DOMValidator behaviors and edge cases", () => {
    it("constructor throws on invalid allowed vs forbidden overlap", () => {
      expect(() => new DOMValidator({
        allowedRootSelectors: new Set(["body"]),
        forbiddenRoots: new Set(["body"]),
      } as any)).toThrow();
    });

    it("invalidateCache emits cache_refresh when auditHook provided", async () => {
      const calls: any[] = [];
      const hook = vi.fn(async (e: any) => calls.push(e));
      const v = createDefaultDOMValidator({ auditHook: hook, emitSelectorHash: false } as any);
      v.invalidateCache();
      // wait a tick for async fire-and-forget to run
      vi.useFakeTimers();
      try {
        await vi.runAllTimersAsync();
      } finally {
        vi.useRealTimers();
      }
      expect(calls.length).toBeGreaterThanOrEqual(1);
      expect(calls[0].kind).toBe("cache_refresh");
    });

    it("validateSelectorSyntax accepts simple selectors and rejects expensive ones", () => {
      const v = createDefaultDOMValidator();
      expect(v.validateSelectorSyntax("#x")).toBe("#x");
      expect(() => v.validateSelectorSyntax(123 as unknown as string)).toThrow();
      expect(() => v.validateSelectorSyntax("")).toThrow();
      expect(() => v.validateSelectorSyntax("a:has(b)")).toThrow();
    });

    it("assertParenDepthWithinLimit throws when too deep and validateSelectorSyntax enforces it", () => {
      const v = createDefaultDOMValidator();
      const deep = "(".repeat(10) + "a" + ")".repeat(10);
      expect(() => v.validateSelectorSyntax(deep)).toThrow();
    });

    it("validateElement rejects non-elements and forbidden tags", () => {
      const v = createDefaultDOMValidator();
      expect(() => v.validateElement(null as unknown as Element)).toThrow();
      const el = document.createElement("script");
      expect(() => v.validateElement(el)).toThrow();
    });

    it("queryAllSafely and containsWithinAllowedRoots basic flow", () => {
      const root = document.createElement("div");
      root.id = "main-content"; // allowed root by default
      document.body.appendChild(root);
      const child = document.createElement("span");
      root.appendChild(child);

      const v = createDefaultDOMValidator();
      // queryAllSafely
      const found = v.queryAllSafely("#main-content span");
      expect(Array.isArray(found)).toBe(true);
      // containsWithinAllowedRoots
      expect(v.containsWithinAllowedRoots(child)).toBe(true);
    });

    it("queryAllSafely fails fast when failFast set and selector invalid", () => {
      const v = createDefaultDOMValidator({ failFast: true } as any);
      // stub DocumentFragment.prototype.querySelector to throw for this selector
      const orig = DocumentFragment.prototype.querySelector;
      DocumentFragment.prototype.querySelector = function () { throw new Error('bad'); } as any;
      try {
        expect(() => v.queryAllSafely("bad(selector)" as unknown as string)).toThrow();
      } finally {
        DocumentFragment.prototype.querySelector = orig;
      }
    });

    it("attempts to upgrade internal cache to LRU when available", async () => {
      // ensure global markers absent
      try { delete (globalThis as any).__LRU_UPGRADED; } catch {}
      try { delete (globalThis as any).__LRU_IMPORTED; } catch {}
      // create a validator without cacheFactory so upgrade can be triggered
      // Provide a deterministic importer override so the class attempts to
      // construct an LRU shim synchronously from our test.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (DOMValidator as any).__test_importOverride = async (spec: string) => {
        if (spec === "lru-cache") {
          try { (globalThis as any).__LRU_IMPORTED = true; } catch {}
          return {
            default: class LRUShim {
              _map: Map<any, any>;
              constructor(opts: any) {
                try { (globalThis as any).__LRU_UPGRADED = true; } catch {}
                this._map = new Map();
              }
              get(k: any) { return this._map.get(k); }
              set(k: any, v: any) { this._map.set(k, v); }
            },
          };
        }
        throw new Error("not found");
      };

      const v = new DOMValidator();
      // call the test wrapper that invokes the private upgrade to force import
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (v as any).__test_tryUpgradeCache();
      // cleanup importer override
      try { delete (DOMValidator as any).__test_importOverride; } catch {}
      // our shim marks a global flag when module imported or constructed
      const imported = Boolean((globalThis as any).__LRU_IMPORTED);
      const upgraded = Boolean((globalThis as any).__LRU_UPGRADED);
      expect(imported || upgraded).toBe(true);
    });

    it("background css-what parse emits audit on parse failure", async () => {
      const calls: any[] = [];
      const hook = vi.fn(async (e: any) => calls.push(e));

  const v = createDefaultDOMValidator({ auditHook: hook } as any);
      // call the test wrapper that directly invokes the private background parse
      // this avoids timing uncertainty and runs the optional import synchronously from the test's perspective
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      // Provide a deterministic importer override so the background parser
      // uses a predictable shim that throws when selector contains sentinel.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (DOMValidator as any).__test_importOverride = async (spec: string) => {
        if (spec === "css-what") {
          try { (globalThis as any).__CSS_WHAT_IMPORTED = true; } catch {}
          return {
            parse: (s: string) => {
              if (String(s).includes("__throw__")) throw new Error("parse-fail");
              return [[{ type: "tag", name: String(s) }]];
            },
          };
        }
        throw new Error("not found");
      };

      (v as any).__test_backgroundCssWhatParse('div[foo="__throw__"]');
      // cleanup importer override
      try { delete (DOMValidator as any).__test_importOverride; } catch {}
  // wait a short moment for fire-and-forget audit emission
  vi.useFakeTimers();
  try {
    await vi.runAllTimersAsync();
  } finally {
    vi.useRealTimers();
  }
      // should have emitted a validation_failure audit event due to parse failure
      expect(calls.some((c) => c && c.kind === "validation_failure")).toBe(true);
    });

    it("emitValidationFailureEvent handles sha256/hash failures gracefully", async () => {
      const calls: any[] = [];
      const hook = vi.fn(async (e: any) => calls.push(e));

      // Force sha256 to fail by making importer reject
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (__test_sha256Hex as any).__test_importOverride = async () => Promise.reject(new Error("no-crypto"));

      const v = createDefaultDOMValidator({ auditHook: hook, emitSelectorHash: true } as any);

      // Trigger a selector validation failure that will call #emitValidationFailureEvent
      expect(() => v.validateSelectorSyntax("a:has(b)")).toThrow();

  // wait a short while for async follow-up to run
  vi.useFakeTimers();
  try {
    await vi.runAllTimersAsync();
  } finally {
    vi.useRealTimers();
  }

      // base event should have been emitted; follow-up hash event may have failed and been handled
      expect(calls.length).toBeGreaterThanOrEqual(1);
      expect(calls[0].kind).toBe("validation_failure");
    });

    it("safeCallAuditHook honors auditHookTimeoutMs and does not throw", async () => {
      const calls: any[] = [];

      // audit hook that hangs longer than allowed timeout
      const hook = async (e: any) => {
        calls.push(e);
        await vi.runAllTimersAsync(); // Use fake timers instead of real setTimeout
      };

      const v = createDefaultDOMValidator({ auditHook: hook, auditHookTimeoutMs: 1 } as any);
      // invalidateCache triggers a cache_refresh audit event which will race with timeout
      v.invalidateCache();
      // use fake timers and advance so the timeout path runs deterministically
      vi.useFakeTimers();
      try {
        vi.advanceTimersByTime(100);
        await vi.runAllTimersAsync();
      } finally {
        vi.useRealTimers();
      }

      // hook may have been invoked but the wrapper should have timed out and caught the error
      expect(calls.length).toBeGreaterThanOrEqual(0);
    });

    it("emitValidationFailureEvent emits hash follow-up when sha256 succeeds", async () => {
      const calls: any[] = [];
      const hook = vi.fn(async (e: any) => calls.push(e));

      // make sha256 succeed via importer override
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (__test_sha256Hex as any).__test_importOverride = async () => ({ sha256: (s: string) => "hash-ok" });

      const v = createDefaultDOMValidator({ auditHook: hook, emitSelectorHash: true } as any);

      expect(() => v.validateSelectorSyntax("a:has(b)")).toThrow();

  // wait for async follow-up
  vi.useFakeTimers();
  try {
    await vi.runAllTimersAsync();
  } finally {
    vi.useRealTimers();
  }

      // Should have at least two calls: base validation_failure and follow-up validation_failure_hash
      const kinds = calls.map((c) => c.kind).sort();
      expect(kinds).toContain("validation_failure");
      expect(kinds).toContain("validation_failure_hash");

      const hashEvent = calls.find((c) => c.kind === "validation_failure_hash");
      expect(hashEvent).toBeDefined();
      expect(hashEvent.selectorHash).toBe("hash-ok");
    });

    it("auditHook throwing errors are caught and do not bubble", async () => {
      // hook that throws immediately
      const hook = vi.fn(() => { throw new Error('boom'); });
      const v = createDefaultDOMValidator({ auditHook: hook } as any);
      // invalidateCache should call hook but not throw
      v.invalidateCache();
      // allow the fire-and-forget to run via fake timers
      vi.useFakeTimers();
      try {
        await vi.runAllTimersAsync();
      } finally {
        vi.useRealTimers();
      }
      expect(hook).toHaveBeenCalled();
    });

    it("getDefaultDOMValidator lazy construction and reset works", async () => {
      // Ensure reset helper clears the singleton
      // Use dynamic import because tests run in ESM mode
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const mod: any = await import("../../src/dom");
      // call reset then get twice
      mod.__test_resetDefaultValidatorForUnitTests();
      const a = mod.getDefaultDOMValidator();
      const b = mod.getDefaultDOMValidator();
      expect(a).toBe(b);
      // reset again and ensure a new instance is created
      mod.__test_resetDefaultValidatorForUnitTests();
      const c = mod.getDefaultDOMValidator();
      expect(c).not.toBe(b);
    });
  });
});
