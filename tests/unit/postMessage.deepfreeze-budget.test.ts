import { describe, it, expect, vi } from "vitest";

describe("postMessage deepFreeze budget", () => {
  it("respects deepFreeze node budget and still calls handler", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => ({ getRandomValues: (b: Uint8Array) => b, subtle: undefined } as any));

    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();
    // Create a very wide object to exceed small node budget
    const wide: any = {};
    for (let i = 0; i < 2000; i++) wide[`k${i}`] = i;

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: (_d: unknown) => true,
      // reduce deepFreeze budget via option
      deepFreezeNodeBudget: 10,
    } as any);

    const ev = new MessageEvent("message", { data: JSON.stringify(wide), origin: "http://localhost", source: window as any });
    window.dispatchEvent(ev);
    await new Promise((r) => setTimeout(r, 10));
    listener.destroy();
    expect(onMessage).toHaveBeenCalledTimes(1);
  });
});
