import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage structured wire format", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("accepts structured-clone payloads when wireFormat=structured", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    vi.spyOn(state, "ensureCrypto").mockImplementation(
      async () =>
        ({ getRandomValues: (b: Uint8Array) => b, subtle: undefined }) as any,
    );

    const postMessage = await import("../../src/postMessage");
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: (d) => true,
      wireFormat: "structured",
    });

    const payload = { nested: { ok: 1 } };
    const ev = new MessageEvent("message", {
      data: payload,
      origin: "http://localhost",
      source: window as any,
    });
    window.dispatchEvent(ev);
    // small wait to allow handler
    await vi.runAllTimersAsync();
    listener.destroy();
    expect(onMessage).toHaveBeenCalledTimes(1);
    const calledWith = onMessage.mock.calls[0][0];
    expect(calledWith).toEqual({ nested: { ok: 1 } });
  });

  it("auto accepts structured only same-origin", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    vi.spyOn(state, "ensureCrypto").mockImplementation(
      async () =>
        ({ getRandomValues: (b: Uint8Array) => b, subtle: undefined }) as any,
    );

    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: [location.origin, "http://localhost"],
      onMessage,
      validate: (d) => true,
      wireFormat: "auto",
    });

    // same-origin structured
    const same = new MessageEvent("message", {
      data: { x: 1 },
      origin: location.origin,
      source: window as any,
    });
    window.dispatchEvent(same);
    // cross-origin structured should be rejected
    const cross = new MessageEvent("message", {
      data: { x: 2 },
      origin: "http://example.com",
      source: window as any,
    });
    window.dispatchEvent(cross);
    // wait for scheduled tasks
    await vi.runAllTimersAsync();
    listener.destroy();
    const called = onMessage.mock.calls.map((c) => c[0]);
    // only x:1 should be accepted
    expect(called).toContainEqual({ x: 1 });
    expect(called).not.toContainEqual({ x: 2 });
  });
});
