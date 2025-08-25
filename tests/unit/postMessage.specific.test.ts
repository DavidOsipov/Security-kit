import { describe, it, expect, vi } from "vitest";
import { createSecurePostMessageListener, _validatePayload } from "../../src/postMessage";

describe("postMessage specific hardening tests", () => {
  it("freezePayload default behavior makes payload frozen", () => {
    const onMessage = vi.fn((data: any) => {
      expect(Object.isFrozen(data)).toBe(true);
      if (data && typeof data === 'object') {
        for (const v of Object.values(data as any)) expect(Object.isFrozen(v)).toBe(true);
      }
    });
    const listener = createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
    });
    const ev = new MessageEvent("message", { data: JSON.stringify({ a: 1 }), origin: "http://localhost", source: window });
    window.dispatchEvent(ev);
    expect(onMessage).toHaveBeenCalled();
    listener.destroy();
  });

  it("_validatePayload ignores symbol-keyed properties and rejects forbidden names", () => {
    const schema = { a: "string" as const };
    const o: any = { a: "x" };
    const sym = Symbol("s");
    o[sym] = { hidden: true };
    // symbol keys shouldn't affect schema validation
    expect(_validatePayload(o, schema).valid).toBe(true);
    // forbidden name still rejected
    expect(_validatePayload({ __proto__: {} }, schema).valid).toBe(false);
  });

  it("expectedSource option enforces source equality", () => {
    const onMessage = vi.fn();
    const expected = window; // current window
    const listener = createSecurePostMessageListener({
      allowedOrigins: ["http://localhost"],
      onMessage,
      validate: { a: "number" },
      expectedSource: expected,
    });
    // message with different source (null) should be dropped
    const ev = new MessageEvent("message", { data: JSON.stringify({ a: 1 }), origin: "http://localhost", source: null as any });
    window.dispatchEvent(ev);
    expect(onMessage).not.toHaveBeenCalled();
    // message with expected source should be accepted
    const ev2 = new MessageEvent("message", { data: JSON.stringify({ a: 1 }), origin: "http://localhost", source: expected });
    window.dispatchEvent(ev2);
    expect(onMessage).toHaveBeenCalled();
    listener.destroy();
  });
});
