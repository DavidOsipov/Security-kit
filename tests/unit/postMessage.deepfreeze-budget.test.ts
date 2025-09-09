import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage deepFreeze budget", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("respects deepFreeze node budget and still calls handler", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    vi.spyOn(state, "ensureCrypto").mockImplementation(
      async () =>
        ({ getRandomValues: (b: Uint8Array) => b, subtle: undefined }) as any,
    );

    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    // Create a nested structure that stays within sanitizer breadth caps
    // but exceeds deepFreeze node budget during freezing.
    const wide: any = { items: [] as any[] };
    for (let i = 0; i < 50; i++) {
      wide.items.push({ x: i, y: { z: i } });
    }

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: (_d: unknown) => true,
      // reduce deepFreeze budget via option
      deepFreezeNodeBudget: 10,
    } as any);

    const ev = new MessageEvent("message", {
      data: JSON.stringify(wide),
      origin: "http://localhost",
      source: window as any,
    });
    window.dispatchEvent(ev);
    await vi.runAllTimersAsync();
    listener.destroy();
    expect(onMessage).toHaveBeenCalledTimes(1);
  });
});
