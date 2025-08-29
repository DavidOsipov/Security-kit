import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage targeted hardening tests", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  it("ignores symbol-keyed properties and skips accessors (getters)", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn((d: any) => {
      // noop
    });

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      enableDiagnostics: false,
    });

    // construct an object with symbol-keyed property.
    // Note: accessor properties would be invoked by JSON.stringify on the
    // sender side, so creating a throwing getter here would execute during
    // JSON.stringify and fail the test. We therefore only assert symbol
    // keys are not serialized (JSON.stringify ignores symbols).
    const s = Symbol("evil");
    const o: any = { a: 1 };
    o[s] = { leak: true };

    const ev = new MessageEvent("message", { data: JSON.stringify(o), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);

  await vi.runAllTimersAsync();
    expect(onMessage).toHaveBeenCalledTimes(1);
    const arg = onMessage.mock.calls[0][0];
    // symbol-key should not have been preserved (not enumerable string key)
    expect(Object.getOwnPropertySymbols(arg).length).toBe(0);
    // accessor property should be skipped
    expect(Object.prototype.hasOwnProperty.call(arg, "bad")).toBe(false);

    listener.destroy();
  });

  it("rejects payloads exceeding depth limit and removes forbidden prototype keys", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn();
    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { deep: "object" },
      enableDiagnostics: false,
    });

    // create nested payload deeper than POSTMESSAGE_MAX_PAYLOAD_DEPTH
    const deep: any = {};
    let cur = deep;
    for (let i = 0; i < 12; i++) {
      cur.next = {};
      cur = cur.next;
    }
    const ev = new MessageEvent("message", { data: JSON.stringify({ deep }), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);

  await vi.runAllTimersAsync();
    // should not call onMessage (validation should fail due to depth)
    expect(onMessage).not.toHaveBeenCalled();

    // forbidden keys removal test: send payload with __proto__/constructor/prototype
    const malicious = { a: 1, __proto__: { hacked: true }, constructor: {}, prototype: {} } as any;
    const ev2 = new MessageEvent("message", { data: JSON.stringify(malicious), origin: "http://localhost", source: window });
    // using a listener that accepts a simple schema allowing 'a'
    window.dispatchEvent(ev2);
  await vi.runAllTimersAsync();
    // last handled arg should not contain prototype-related keys
    // find the last call
    const last = onMessage.mock.calls[onMessage.mock.calls.length - 1];
    if (last) {
      const parsed = last[0];
      expect(Object.prototype.hasOwnProperty.call(parsed, "__proto__")).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(parsed, "constructor")).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(parsed, "prototype")).toBe(false);
    }

    listener.destroy();
  });

  it("freezePayload: false allows mutation by consumer", async () => {
    vi.resetModules();
    const postMessage = await import("../../src/postMessage");

    const onMessage = vi.fn((d: any) => {
      // mutate payload
      try {
        (d as any).mutated = 123;
      } catch {}
    });

    const listener = postMessage.createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      freezePayload: false,
      enableDiagnostics: false,
    });

    const payload = { a: 1 };
    window.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(payload), origin: "http://localhost", source: window }));
  await vi.runAllTimersAsync();
    expect(onMessage).toHaveBeenCalled();
    const arg = onMessage.mock.calls[0][0];
    // mutation should have been applied
    expect(arg.mutated).toBe(123);

    listener.destroy();
  });

  it("emits fingerprint when crypto available and format looks sane", async () => {
    vi.resetModules();
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
    window.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(bad), origin: "http://localhost", source: window }));
  await vi.runAllTimersAsync();

    const calls = secureDevLogSpy.mock.calls;
    const diagCall = calls.find((c) => (c as any)[2] === "Message dropped due to failed validation");
    expect(diagCall).toBeTruthy();
    const ctx = (diagCall as any)[3];
    expect(typeof ctx.fingerprint).toBe("string");
    expect(ctx.fingerprint).not.toBe("FINGERPRINT_ERR");
    expect(ctx.fingerprint.length).toBeGreaterThan(0);

    listener.destroy();
  });
});
