import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const DEFAULT_DIAGNOSTIC_BUDGET = 5;

describe("postMessage diagnostics - refill and transient crypto failures", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("refills diagnostic budget after time window", async () => {
    vi.resetModules();
    // Use fake timers for deterministic timing control

    const state = await import("../../src/state");
    const fakeSubtle = {
      digest: async () => new Uint8Array([7, 7, 7, 7]).buffer,
    } as any;
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: fakeSubtle,
    } as any;
    vi.spyOn(state, "ensureCrypto").mockImplementation(
      async () => fakeCrypto as any,
    );

    const utils = await import("../../src/utils");
    // Spy on console.warn (used by _devConsole for 'warn' level) to capture logged context
    const consoleWarnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {});

    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      enableDiagnostics: true,
    });

    const bad = { a: "no" };
    // send exactly the budget number of messages (should consume all budget)
    for (let i = 0; i < DEFAULT_DIAGNOSTIC_BUDGET; i++) {
      const ev = new MessageEvent("message", {
        data: JSON.stringify(bad),
        origin: "http://localhost",
        source: window,
      });
      window.dispatchEvent(ev);
      // Advance fake timers to allow any scheduled timeouts and microtasks
      vi.advanceTimersByTime(10);
      await Promise.resolve();
    }

    // Wait for background tasks to finish
    vi.advanceTimersByTime(100);
    await Promise.resolve();

    // helper: advance timers and flush microtasks until spy has at least minCalls
    function parseContextFromLogArg(arg: unknown): any | undefined {
      if (typeof arg !== "string") return undefined;
      const idx = arg.indexOf("context=");
      if (idx === -1) return undefined;
      const json = arg.slice(idx + "context=".length);
      try {
        return JSON.parse(json);
      } catch {
        return undefined;
      }
    }

    async function waitForConsoleWarnCalls(minCalls: number, maxIter = 50) {
      for (let i = 0; i < maxIter; i++) {
        const calls = (consoleWarnSpy.mock.calls as Array<any[]>).filter(
          (c) => {
            const arg0 = c[0];
            if (typeof arg0 !== "string") return false;
            if (
              !arg0.includes("(postMessage)") ||
              !arg0.includes("Message dropped due to failed validation")
            )
              return false;
            const ctx = parseContextFromLogArg(arg0);
            return !!(ctx && typeof ctx.fingerprint === "string");
          },
        );
        if (calls.length >= minCalls) return calls;
        vi.advanceTimersByTime(20);
        await Promise.resolve();
      }
      return (consoleWarnSpy.mock.calls as Array<any[]>).filter((c) => {
        const arg0 = c[0];
        if (typeof arg0 !== "string") return false;
        if (
          !arg0.includes("(postMessage)") ||
          !arg0.includes("Message dropped due to failed validation")
        )
          return false;
        const ctx = parseContextFromLogArg(arg0);
        return !!(ctx && typeof ctx.fingerprint === "string");
      });
    }

    const captured1 = await waitForConsoleWarnCalls(1);

    expect(captured1.length).toBeGreaterThan(0);
    expect(captured1.length).toBeLessThanOrEqual(DEFAULT_DIAGNOSTIC_BUDGET);

    // advance time beyond refill window deterministically
    vi.advanceTimersByTime(65000);
    await Promise.resolve();

    // send one more message which should be fingerprinted after refill
    const ev2 = new MessageEvent("message", {
      data: JSON.stringify(bad),
      origin: "http://localhost",
      source: window,
    });
    window.dispatchEvent(ev2);
    // wait for the post-refill fingerprinted call(s)
    const captured2 = await waitForConsoleWarnCalls(captured1.length + 1);

    expect(captured2.length).toBeGreaterThan(captured1.length);

    listener.destroy();
    consoleWarnSpy.mockRestore();
  }, 120000); // 2 minute timeout

  it("transient ensureCrypto failure then recovery allows later fingerprinting", async () => {
    // Use fake timers for deterministic control
    vi.resetModules();
    // Ensure test APIs are allowed so we can call internals if needed
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

    const state = await import("../../src/state");
    let calls = 0;
    const fakeSubtle = {
      digest: async () => new Uint8Array([5, 5, 5, 5]).buffer,
    } as any;
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: fakeSubtle,
    } as any;

    // First call fails, second call succeeds deterministically
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => {
      calls++;
      if (calls === 1) {
        throw new Error("temporary failure");
      }
      return fakeCrypto as any;
    });

    const utils = await import("../../src/utils");
    const consoleWarnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => {});

    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      enableDiagnostics: true,
    });

    const bad = { a: "no" };

    // Clear any previous captured logs
    consoleWarnSpy.mockClear();

    // first message will trigger ensureCrypto rejection and no fingerprint
    const ev1 = new MessageEvent("message", {
      data: JSON.stringify(bad),
      origin: "http://localhost",
      source: window,
    });
    window.dispatchEvent(ev1);

    // Allow any pending microtasks to run (hand-crafted promise)
    await Promise.resolve();
    vi.advanceTimersByTime(50);
    await Promise.resolve();

    const callsAfter1 = (consoleWarnSpy.mock.calls as Array<any[]>).filter(
      (c) => {
        const arg0 = c[0];
        if (typeof arg0 !== "string") return false;
        if (
          !arg0.includes("(postMessage)") ||
          !arg0.includes("Message dropped due to failed validation")
        )
          return false;
        const ctx = (() => {
          const idx = arg0.indexOf("context=");
          if (idx === -1) return undefined;
          try {
            return JSON.parse(arg0.slice(idx + "context=".length));
          } catch {
            return undefined;
          }
        })();
        return !!(ctx && typeof ctx.fingerprint === "string");
      },
    );

    // no fingerprint yet - ensureCrypto failed
    expect(callsAfter1.length).toBe(0);

    // Clear captured logs for second message
    consoleWarnSpy.mockClear();

    // second message should succeed (ensureCrypto returns crypto) and produce fingerprint
    const ev2 = new MessageEvent("message", {
      data: JSON.stringify(bad),
      origin: "http://localhost",
      source: window,
    });
    window.dispatchEvent(ev2);

    // Allow microtasks and timers to settle
    await Promise.resolve();
    vi.advanceTimersByTime(50);
    await Promise.resolve();

    // wait for the fingerprinted call to appear deterministically
    async function waitForConsoleWarnCallsLocal(
      minCalls: number,
      maxIter = 50,
    ) {
      for (let i = 0; i < maxIter; i++) {
        const calls = (consoleWarnSpy.mock.calls as Array<any[]>).filter(
          (c) => {
            const arg0 = c[0];
            if (typeof arg0 !== "string") return false;
            if (
              !arg0.includes("(postMessage)") ||
              !arg0.includes("Message dropped due to failed validation")
            )
              return false;
            const idx = arg0.indexOf("context=");
            if (idx === -1) return false;
            try {
              const ctx = JSON.parse(arg0.slice(idx + "context=".length));
              return !!(ctx && typeof ctx.fingerprint === "string");
            } catch {
              return false;
            }
          },
        );
        if (calls.length >= minCalls) return calls;
        vi.advanceTimersByTime(20);
        await Promise.resolve();
      }
      return (consoleWarnSpy.mock.calls as Array<any[]>).filter((c) => {
        const arg0 = c[0];
        if (typeof arg0 !== "string") return false;
        if (
          !arg0.includes("(postMessage)") ||
          !arg0.includes("Message dropped due to failed validation")
        )
          return false;
        const idx = arg0.indexOf("context=");
        if (idx === -1) return false;
        try {
          const ctx = JSON.parse(arg0.slice(idx + "context=".length));
          return !!(ctx && typeof ctx.fingerprint === "string");
        } catch {
          return false;
        }
      });
    }

    const callsAfter2 = await waitForConsoleWarnCallsLocal(1);

    expect(callsAfter2.length).toBeGreaterThan(0);

    listener.destroy();
    // timers restored in afterEach
  });
});
