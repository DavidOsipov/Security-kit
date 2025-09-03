import { afterEach, describe, expect, it, vi, beforeEach } from "vitest";
import * as utils from "../../src/utils";
import {
  createDefaultDOMValidator,
  __test_resetDefaultValidatorForUnitTests,
  __test_sha256Hex,
} from "../../src/dom";

describe("dom.ts uncovered branches", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers();
  });

  afterEach(() => {
    // restore any test-only overrides and reset default singleton
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ((__test_sha256Hex as any).__test_importOverride)
        delete (__test_sha256Hex as any).__test_importOverride;
    } catch {
      /* swallow */
    }
    __test_resetDefaultValidatorForUnitTests();
    vi.restoreAllMocks();
  });

  it("queryAllSafely handles parser rejection and returns empty array (hits catch/log path)", () => {
    const v = createDefaultDOMValidator();
    // Use a syntactically-broken selector that native parser should reject
    const res = v.queryAllSafely("div[");
    expect(res).toEqual([]);
  });

  it("queryAllSafely throws when failFast is enabled and parser rejects", () => {
    const v = createDefaultDOMValidator({ failFast: true });
    expect(() => v.queryAllSafely("div[")).toThrow();
  });

  it("emitValidationFailureEvent follow-up hash failure is handled (no hash emitted)", async () => {
    // Temporarily remove WebCrypto so sha256Hex goes through dynamic-import paths
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const originalCrypto = (globalThis as any).crypto;
    // delete crypto to force fallback
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (globalThis as any).crypto;
    } catch {
      /* swallow */
    }

    // Make importer always reject so sha256Hex ultimately throws
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (__test_sha256Hex as any).__test_importOverride = async (_spec: string) =>
      Promise.reject(new Error("no module"));

    const events: unknown[] = [];
    const v = createDefaultDOMValidator({
      auditHook: (e) => {
        events.push(e);
        return undefined;
      },
      emitSelectorHash: true,
    });

    // trigger a validation failure by passing a non-element to validateElement
    await expect(async () =>
      v.validateElement("not-an-element" as unknown),
    ).rejects.toThrow();

    // allow background follow-up IIFE to run (give more time for async follow-up)
    vi.useFakeTimers();
    try {
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }

    // base validation_failure should be present; follow-up validation_failure_hash should NOT
    expect(
      events.some((e: any) => e && e.kind === "validation_failure"),
    ).toBeTruthy();
    expect(
      events.some((e: any) => e && e.kind === "validation_failure_hash"),
    ).toBeFalsy();

    // restore crypto
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).crypto = originalCrypto;
  });

  it("safeCallAuditHook swallow branch - auditHook timeout path is handled", async () => {
    const calls: unknown[] = [];
    // Hook that never resolves to force a timeout
    const hangingHook = vi.fn((): Promise<void> => {
      calls.push("called");
      return new Promise<void>(() => {
        /* never resolves */
      });
    });

    const v = createDefaultDOMValidator({
      auditHook: hangingHook,
      auditHookTimeoutMs: 10,
    });
    // invalidateCache triggers a fire-and-forget call to #safeCallAuditHook which should timeout
    v.invalidateCache();

    // wait enough for timeout-based branch to execute
    await vi.runAllTimersAsync();

    expect(calls.length).toBeGreaterThan(0);
  });

  it("queryAllSafely logs when validateElement throws for matched elements (covers element-validation catch)", () => {
    // Ensure an allowed root exists
    const root = document.createElement("div");
    root.id = "main-content";
    document.body.appendChild(root);
    // Add a forbidden child (script) that will trigger validateElement to throw
    const script = document.createElement("script");
    root.appendChild(script);
    const v = createDefaultDOMValidator();
    const res = v.queryAllSafely("script");
    expect(res).toEqual([]);
    // cleanup
    root.remove();
  });

  it("refresh root: handles document.querySelector throwing during root refresh", () => {
    const root = document.createElement("div");
    root.id = "main-content";
    document.body.appendChild(root);

    const v = createDefaultDOMValidator();
    // populate cache
    v.queryAllSafely("div");

    // remove the root so cached entry is not connected
    root.remove();

    // stub document.querySelector to throw when asked about the root selector
    // store original
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const orig = (document as any).querySelector;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (document as any).querySelector = (sel: string) => {
      if (sel === "#main-content") throw new Error("bad selector");
      return orig.call(document, sel);
    };

    // ensure we have some matching nodes for the selector used in queryAllSafely
    const span = document.createElement("span");
    document.body.appendChild(span);

    const res = v.queryAllSafely("span");
    expect(res).toEqual([]);

    // cleanup
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (document as any).querySelector = orig;
    span.remove();
  });

  it("refresh root: successful refresh when a new root element is present", () => {
    const root = document.createElement("div");
    root.id = "main-content";
    document.body.appendChild(root);

    const v = createDefaultDOMValidator();
    // populate cache
    v.queryAllSafely("div");

    // remove the original root so cached entry is not connected
    root.remove();

    // now add a new element that matches the same selector
    const newRoot = document.createElement("div");
    newRoot.id = "main-content";
    document.body.appendChild(newRoot);

    // ensure we have a matching node inside the refreshed root
    const span = document.createElement("span");
    newRoot.appendChild(span);

    const res = v.queryAllSafely("span");
    // span should be found and validated (validateElement allows span)
    expect(res.length).toBeGreaterThanOrEqual(1);

    // cleanup
    newRoot.remove();
  });

  it("emitValidationFailureEvent inner catch executes when secureDevLog throws and sha256 fails", async () => {
    // remove WebCrypto to force sha256 fallback
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const origCrypto = (globalThis as any).crypto;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).crypto;

    // force sha256 dynamic imports to reject
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (__test_sha256Hex as any).__test_importOverride = async (_spec: string) =>
      Promise.reject(new Error("no module"));

    // make secureDevLog throw
    const spy = vi.spyOn(utils, "secureDevLog").mockImplementation(() => {
      throw new Error("log fail");
    });

    const events: unknown[] = [];
    const v = createDefaultDOMValidator({
      auditHook: (e) => {
        events.push(e);
        return undefined;
      },
      emitSelectorHash: true,
    });

    await expect(async () =>
      v.validateElement("not-an-element" as unknown),
    ).rejects.toThrow();

    // wait for async follow-up
    await vi.runAllTimersAsync();

    expect(
      events.some((e: any) => e && e.kind === "validation_failure"),
    ).toBeTruthy();

    spy.mockRestore();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).crypto = origCrypto;
  });

  it("emitValidationFailureEvent inner logging catch is exercised when logging throws", async () => {
    // make secureDevLog throw so the inner catch path is executed
    const spy = vi.spyOn(utils, "secureDevLog").mockImplementation(() => {
      throw new Error("log fail");
    });

    // force sha256 importer to reject so emitValidationFailureEvent goes into catch
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (__test_sha256Hex as any).__test_importOverride = async (_spec: string) =>
      Promise.reject(new Error("no module"));

    const events: unknown[] = [];
    const v = createDefaultDOMValidator({
      auditHook: (e) => {
        events.push(e);
        return undefined;
      },
      emitSelectorHash: true,
    });

    await expect(async () =>
      v.validateElement("not-an-element" as unknown),
    ).rejects.toThrow();

    // advance timers so background processing runs
    vi.useFakeTimers();
    try {
      vi.advanceTimersByTime(500);
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }

    // base event was emitted, and inner logging threw but was swallowed
    expect(
      events.some((e: any) => e && e.kind === "validation_failure"),
    ).toBeTruthy();
    spy.mockRestore();
  });

  it("safeCallAuditHook inner logging catch is exercised when secureDevLog throws", async () => {
    const spy = vi.spyOn(utils, "secureDevLog").mockImplementation(() => {
      throw new Error("log fail");
    });

    const events: unknown[] = [];
    const v = createDefaultDOMValidator({
      auditHook: async () => {
        // reject to trigger safeCallAuditHook's catch
        throw new Error("hook error");
      },
    });

    v.invalidateCache();
    await vi.runAllTimersAsync();
    // no exception should propagate even though secureDevLog threw inside catch
    spy.mockRestore();
  });
});
