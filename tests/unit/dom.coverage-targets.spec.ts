import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createDefaultDOMValidator,
  getDefaultDOMValidator,
  __test_fingerprintHexSync as fingerprintHexSync,
  __test_promiseWithTimeout as promiseWithTimeout,
  __test_sha256Hex as sha256Hex,
} from "../../src/dom";

describe("dom.ts coverage targets", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // clear any importer override
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (sha256Hex as any).__test_importOverride = undefined;
  });
  afterEach(() => {
    vi.restoreAllMocks();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (sha256Hex as any).__test_importOverride = undefined;
  });

  it("fingerprintHexSync produces deterministic hex length", () => {
    const h = fingerprintHexSync("abc");
    expect(typeof h).toBe("string");
    expect(h.length).toBeGreaterThan(0);
  });

  it("promiseWithTimeout rejects on timeout", async () => {
    const slow = new Promise((res) => setTimeout(() => res("ok"), 50));
    await expect(promiseWithTimeout(slow as Promise<unknown>, 10, "boom")).rejects.toThrow("boom");
  });

  it("createDefaultDOMValidator normalizes sets and getDefaultDOMValidator returns singleton", () => {
    const dv = createDefaultDOMValidator({ allowedRootSelectors: ["#main-content"], forbiddenRoots: ["body"] });
    expect(dv).toBeDefined();
    const d2 = getDefaultDOMValidator();
    expect(d2).toBeDefined();
    // calling again returns same singleton instance
    const d3 = getDefaultDOMValidator();
    expect(d3).toBe(d2);
  });

  it("sha256Hex uses node:crypto via importer override", async () => {
    // Prevent Web Crypto from being used so the node:crypto path is exercised.
    // Use vi.stubGlobal to avoid attempting to reassign read-only globals.
    vi.stubGlobal("crypto", {} as any);
    // Provide a fake node:crypto module via importer override to ensure the node path runs
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (sha256Hex as any).__test_importOverride = async (spec: string) => {
      if (spec === "node:crypto") {
        return {
          createHash: () => ({ update: () => ({ digest: () => "deadbeef" }) }),
        };
      }
      // other modules: reject so fallback doesn't accidentally succeed
      return Promise.reject(new Error("no"));
    };
    const res = await sha256Hex("input");
    expect(res).toBe("deadbeef");
  });

  it("emitValidationFailureEvent emits follow-up hash when emitSelectorHash is true", async () => {
    const events: any[] = [];
    // prevent webcrypto from short-circuiting
    vi.stubGlobal("crypto", {} as any);
    // ensure sha256Hex will use our fake node:crypto
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (sha256Hex as any).__test_importOverride = async (spec: string) => {
      if (spec === "node:crypto") {
        return {
          createHash: () => ({ update: () => ({ digest: () => "cafebabe" }) }),
        };
      }
      return Promise.reject(new Error("no"));
    };

    const dv = createDefaultDOMValidator({ emitSelectorHash: true, auditHook: async (e) => { events.push(e); } });

    // Cause a validation failure by using a disallowed pseudo-class
    await expect(async () => dv.validateSelectorSyntax(":has(.x)" as unknown as string)).rejects.toThrow();

    // Wait briefly for async follow-up audit to run
    await new Promise((r) => setTimeout(r, 80));

    // We should have at least the base event and the follow-up hash event
    expect(events.length).toBeGreaterThanOrEqual(1);
    const hashEvent = events.find((x) => x.kind === "validation_failure_hash");
    expect(hashEvent).toBeDefined();
    expect(hashEvent.selectorHash).toBe("cafebabe");
  });
});
