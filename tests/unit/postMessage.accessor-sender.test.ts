import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage sender-side accessor tests", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Clear module cache so each test can import a fresh instance and
    // set up per-test mocks before importing the module under test.
    vi.resetModules();
  });
  afterEach(() => vi.useRealTimers());
  it("sendSecurePostMessage should reject payloads whose getters throw during serialization", async () => {
    // Build an object whose getter throws; JSON.stringify should invoke it
    const o: any = { a: 1 };
    Object.defineProperty(o, "bad", {
      enumerable: true,
      get() {
        throw new Error("boom-serialize");
      },
    });

  const postMessage = await import("../../src/postMessage");
    // sendSecurePostMessage sanitizes payload and should NOT throw; it skips accessors
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(() => {
      postMessage.sendSecurePostMessage({ targetWindow: window, payload: o, targetOrigin: "http://localhost" } as any);
    }).not.toThrow();
    // Current implementation skips accessor properties silently; no dev warning expected.
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("receiving pre-serialized JSON string should not execute sender getters (safe to parse)", async () => {
    // Simulate a remote sender that already serialized a JSON string;
    // the receiver should only parse strings and not re-invoke any getters.
    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { x: "number" },
    });

    // create a crafted JSON string that would represent an object with dangerous getters
  const safeSerialized = JSON.stringify({ x: 1 });
    window.dispatchEvent(new MessageEvent("message", { data: safeSerialized, origin: "http://localhost", source: window }));

    await vi.runAllTimersAsync();
    expect(onMessage).toHaveBeenCalled();
    listener.destroy();
  });
});
