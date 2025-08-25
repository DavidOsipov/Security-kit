import { describe, it, expect } from "vitest";
import { _validatePayload, _validatePayloadWithExtras } from "../../src/postMessage";

describe("_validatePayload (schema)", () => {
  it("validates simple schema and rejects forbidden keys", () => {
    const schema = { id: "string" as const, n: "number" as const };
    expect(_validatePayload({ id: "x", n: 1 }, schema).valid).toBe(true);
    expect(_validatePayload({ id: "x" }, schema).valid).toBe(false);
    expect(_validatePayload({ id: "x", n: "no" }, schema).valid).toBe(false);
    // forbidden key test
    expect(_validatePayload({ __proto__: {} }, schema).valid).toBe(false);
  });

  it("allows function validators and surfaces thrown errors", () => {
    const fn = (d: unknown) => {
      if (typeof d !== "object" || d == null) throw new Error("bad");
      return true;
    };
    const res = _validatePayload({ a: 1 }, fn as any);
    expect(res.valid).toBe(true);
    const res2 = _validatePayload("no", fn as any);
    expect(res2.valid).toBe(false);
  });
});

describe("_validatePayloadWithExtras", () => {
  it("rejects unexpected extra props when not allowed", () => {
    const schema = { a: "number" as const };
    expect(_validatePayloadWithExtras({ a: 1, b: 2 }, schema, false).valid).toBe(false);
    expect(_validatePayloadWithExtras({ a: 1, b: 2 }, schema, true).valid).toBe(true);
  });
});
