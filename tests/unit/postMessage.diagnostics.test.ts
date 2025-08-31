import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage diagnostics and fingerprinting", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("produces a fingerprint when crypto is available and diagnostics enabled", async () => {
    vi.resetModules();
    // load state and spy ensureCrypto to provide a fake crypto
    const state = await import("../../src/state");
    const fakeSubtle = { digest: async () => new Uint8Array([1, 2, 3, 4]).buffer };
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
      validate: { x: "number" },
      enableDiagnostics: true,
    });

    const bad = { x: "no" };
    const ev = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);

  // wait for queueMicrotask and async fingerprinting scheduled via timers
  await vi.runAllTimersAsync();

    // secureDevLog should be called; find a call with message 'Message dropped due to failed validation' and fingerprint in context
    const calls = secureDevLogSpy.mock.calls;
    const found = calls.some((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });
    listener.destroy();
    expect(found).toBe(true);
  });

  it("disables diagnostics fingerprint when crypto unavailable in production", async () => {
    vi.resetModules();
    // mock environment to production via explicit setter
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

      const onMessage = vi.fn();
      const listener = postMessage.createSecurePostMessageListener({
        allowedOrigins: ["http://localhost"],
        onMessage,
        validate: { x: "number" },
        enableDiagnostics: true,
      });

      const bad = { x: "no" };
      const ev = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
      window.dispatchEvent(ev);

  await vi.runAllTimersAsync();

      const calls = secureDevLogSpy.mock.calls;
      const found = calls.some((c) => {
        try {
          const [, comp, msg, ctx] = c as any;
          // fingerprint should NOT be present in this branch (own property absent)
          return (
            msg === "Message dropped due to failed validation" &&
            ctx &&
            !Object.hasOwn(ctx, "fingerprint")
          );
        } catch {
          return false;
        }
      });
      listener.destroy();
      expect(found).toBe(true);
    } finally {
      // reset environment
      envMod.environment.setExplicitEnv("development");
    }
  });
});
