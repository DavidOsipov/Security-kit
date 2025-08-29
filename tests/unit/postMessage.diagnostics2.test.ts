import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage diagnostics - budget and ensureCrypto error paths", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("rate-limits diagnostic fingerprinting and respects budget", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    // Provide a fake crypto with subtle.digest
    const fakeSubtle = { digest: async () => new Uint8Array([9, 9, 9, 9]).buffer } as any;
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: fakeSubtle,
    } as any;
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => fakeCrypto as any);

    const utils = await import("../../src/utils");
    const secureDevLogSpy = vi.spyOn(utils, "secureDevLog");

    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      enableDiagnostics: true,
    });

    // Send more messages than budget (DEFAULT_DIAGNOSTIC_BUDGET is 5)
    const bad = { a: "no" };
    for (let i = 0; i < 8; i++) {
      const ev = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
      window.dispatchEvent(ev);
      // small delay to allow async fingerprinting to be scheduled
      // but not long enough to refill the budget
  // eslint-disable-next-line no-await-in-loop
  await vi.runAllTimersAsync();
    }

  // allow background tasks to settle
  await vi.runAllTimersAsync();

    // Count fingerprinted logs
    const fpCalls = secureDevLogSpy.mock.calls.filter((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });

    // Should be less than total messages and at most the default budget (5)
    expect(fpCalls.length).toBeGreaterThan(0);
    expect(fpCalls.length).toBeLessThanOrEqual(5);

    listener.destroy();
  });

  it("ensureCrypto rejection disables diagnostics fallback in production", async () => {
    vi.resetModules();
    const envMod = await import("../../src/environment");
    envMod.environment.setExplicitEnv("production");
    try {
      const state = await import("../../src/state");
      vi.spyOn(state, "ensureCrypto").mockImplementation(async () => {
        throw new Error("no crypto");
      });

      const utils = await import("../../src/utils");
      const secureDevLogSpy = vi.spyOn(utils, "secureDevLog");

      const postMessage = await import("../../src/postMessage");

      const listener = postMessage.createSecurePostMessageListener({
        allowedOrigins: ["http://localhost"],
        onMessage: () => undefined,
        validate: { a: "number" },
        enableDiagnostics: true,
      });

      // Dispatch one bad message
      const bad = { a: "no" };
      const ev = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
      window.dispatchEvent(ev);

      await vi.runAllTimersAsync();

      // Ensure that secureDevLog was called but without fingerprint property
      const calls = secureDevLogSpy.mock.calls;
      const foundNoFingerprint = calls.some((c) => {
        try {
          const [, comp, msg, ctx] = c as any;
          return msg === "Message dropped due to failed validation" && ctx && !Object.prototype.hasOwnProperty.call(ctx, "fingerprint");
        } catch {
          return false;
        }
      });

      listener.destroy();
      expect(foundNoFingerprint).toBe(true);
    } finally {
      envMod.environment.setExplicitEnv("development");
    }
  });
});
