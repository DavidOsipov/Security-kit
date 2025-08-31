import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage additional hardening tests", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  it("freezePayload default: payload is deeply frozen when passed to onMessage", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn((d: any) => {
      // attempt mutation should throw in strict mode (frozen)
      try {
        // top-level
        (d as any).newProp = 1;
      } catch {}
      try {
        // nested
        if (d && typeof d === "object" && (d as any).nested)
          (d as any).nested.x = 2;
      } catch {}
    });

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { nested: "object" },
      // use default freezePayload (true)
    });

    const payload = { nested: { x: 1 } };
    const ev = new MessageEvent("message", { data: JSON.stringify(payload), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);

  // give event loop a tick
  await vi.runAllTimersAsync();

    expect(onMessage).toHaveBeenCalled();
    const calledArg = onMessage.mock.calls[0][0];
    // top-level addition should not exist
    expect(Object.hasOwn(calledArg, "newProp")).toBe(false);
    // nested property should remain original value
    expect(calledArg.nested.x).toBe(1);

    listener.destroy();
  });

  it("expectedSource option enforces source equality", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");
    const onMessage = vi.fn();

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { x: "number" },
      expectedSource: window, // only accept messages from same window
    });

    const payload = { x: 1 };
    const ev1 = new MessageEvent("message", { data: JSON.stringify(payload), origin: "http://localhost", source: window });
    window.dispatchEvent(ev1);

    // dispatch from a fake other source (MessagePort) should be dropped
    const fakePort = new MessageChannel().port1;
    const ev2 = new MessageEvent("message", { data: JSON.stringify(payload), origin: "http://localhost", source: fakePort as any });
    window.dispatchEvent(ev2);

  await vi.runAllTimersAsync();
  // only first call should succeed
  expect(onMessage).toHaveBeenCalledTimes(1);

    listener.destroy();
  });

  it("_validatePayload rejects forbidden keys and non-plain objects and handles validator function throwing", async () => {
    const postMessage = await import("../../src/postMessage");

    // forbidden key present
    const r1 = postMessage._validatePayload({ __proto__: { hacked: 1 } }, { a: "number" } as any);
    expect(r1.valid).toBe(false);

    // non-plain object (e.g., function)
    const fn = () => {};
    const r2 = postMessage._validatePayload(fn as any, { a: "number" } as any);
    expect(r2.valid).toBe(false);

    // validator function throws
    const throwing = () => {
      throw new Error("boom");
    };
    const r3 = postMessage._validatePayload(1 as any, throwing as any);
    expect(r3.valid).toBe(false);
    expect(typeof r3.reason).toBe("string");
  });

  it("_validatePayloadWithExtras enforces unexpected property rejection when allowExtraProps=false", async () => {
    const postMessage = await import("../../src/postMessage");
    const r = postMessage._validatePayloadWithExtras({ a: 1, extra: 2 }, { a: "number" });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Unexpected property");
    const r2 = postMessage._validatePayloadWithExtras({ a: 1, extra: 2 }, { a: "number" }, true);
    expect(r2.valid).toBe(true);
  });
});
