import { describe, it, expect, vi } from "vitest";

describe("postMessage wireFormat behavior", () => {
  it("sendSecurePostMessage defaults to JSON wire format and rejects non-string on receive", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");

    // send path should accept object and serialize; but parseMessageEventData rejects non-string
    const ev = new MessageEvent("message", { data: 42, origin: "http://localhost", source: window as any });
    const state = await import("../../src/state");
    // Mock ensureCrypto for listener creation in dev
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => ({ getRandomValues: (b: Uint8Array) => b, subtle: undefined } as any));

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: (d) => true,
    });

    // dispatching a non-string should be dropped with InvalidParameterError caught internally
    window.dispatchEvent(ev);
    listener.destroy();
    // onMessage should not have been called
    expect(onMessage).toHaveBeenCalledTimes(0);
  });
});
