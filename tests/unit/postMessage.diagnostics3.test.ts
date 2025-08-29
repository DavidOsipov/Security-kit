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
    // adjustable performance.now
    const perfNowOrig = performance.now;
    let now = 0;
    (performance as any).now = () => now;

    const state = await import("../../src/state");
    const fakeSubtle = { digest: async () => new Uint8Array([7, 7, 7, 7]).buffer } as any;
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

    const bad = { a: "no" };
    // send exactly the budget number of messages (should consume all budget)
    for (let i = 0; i < DEFAULT_DIAGNOSTIC_BUDGET; i++) {
      const ev = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
      window.dispatchEvent(ev);
      // allow scheduling
  // eslint-disable-next-line no-await-in-loop
  await vi.runAllTimersAsync();
    }

  // let background tasks finish
  await vi.runAllTimersAsync();

    const calls1 = secureDevLogSpy.mock.calls.filter((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });

    expect(calls1.length).toBeGreaterThan(0);
    expect(calls1.length).toBeLessThanOrEqual(DEFAULT_DIAGNOSTIC_BUDGET);


  // advance time beyond refill window
  now += 61_000;
  // because we use fake timers, advance them as well
  vi.setSystemTime(Date.now() + 61_000);

    // send one more message which should be fingerprinted after refill
    const ev2 = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
    window.dispatchEvent(ev2);
  await vi.runAllTimersAsync();

    const calls2 = secureDevLogSpy.mock.calls.filter((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });

    expect(calls2.length).toBeGreaterThan(calls1.length);

    listener.destroy();

    // restore performance
    (performance as any).now = perfNowOrig;
  });

  it("transient ensureCrypto failure then recovery allows later fingerprinting", async () => {
    vi.resetModules();
    // first call throws, second returns crypto
    const state = await import("../../src/state");
    let calls = 0;
    const fakeSubtle = { digest: async () => new Uint8Array([5, 5, 5, 5]).buffer } as any;
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: fakeSubtle,
    } as any;
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => {
      calls++;
      if (calls === 1) throw new Error("temporary failure");
      return fakeCrypto as any;
    });

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

    const bad = { a: "no" };
    // first message will trigger ensureCrypto rejection and no fingerprint
    const ev1 = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
    window.dispatchEvent(ev1);
  await vi.runAllTimersAsync();

    const callsAfter1 = secureDevLogSpy.mock.calls.filter((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });
    // no fingerprint yet
    expect(callsAfter1.length).toBe(0);

    // second message should succeed (ensureCrypto returns crypto) and produce fingerprint
    const ev2 = new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window });
    window.dispatchEvent(ev2);
  await vi.runAllTimersAsync();

    const callsAfter2 = secureDevLogSpy.mock.calls.filter((c) => {
      try {
        const [, comp, msg, ctx] = c as any;
        return msg === "Message dropped due to failed validation" && ctx && (ctx as any).fingerprint;
      } catch {
        return false;
      }
    });

    expect(callsAfter2.length).toBeGreaterThan(0);

    listener.destroy();
  });
});
