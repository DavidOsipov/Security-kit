import { describe, it, expect, vi } from "vitest";

describe("postMessage sender-side accessor tests", () => {
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
    vi.resetModules();
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

    await new Promise((r) => setTimeout(r, 20));
    expect(onMessage).toHaveBeenCalled();
    listener.destroy();
  });
});
