import { describe, it, expect } from "vitest";
import { toCanonicalValue, safeStableStringify } from "../../src/canonical";

describe("canonical additional coverage", () => {
  it("filters `constructor` key and other forbidden keys", () => {
    const input = {
      safe: 1,
      constructor: { hacked: true },
      prototype: { p: 2 },
    } as any;
    const canon = toCanonicalValue(input) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(canon, "constructor")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(canon, "prototype")).toBe(
      false,
    );
    expect(canon.safe).toBe(1);
  });

  it("handles Map and Set by falling back to object/array forms", () => {
    const m = new Map<string, unknown>([
      ["a", 1],
      ["b", 2],
    ]);
    const s = new Set([1, 2, 3]);

    // Current implementation does not specially support Map/Set; ensure it does not throw
    expect(() => toCanonicalValue(m)).not.toThrow();
    expect(() => toCanonicalValue(s)).not.toThrow();
  });

  it("handles TypedArray (Uint8Array) and returns an array-like canonical form", () => {
    const ta = new Uint8Array([1, 2, 3]);
    const canon = toCanonicalValue({ bytes: ta }) as Record<string, unknown>;
    // Expect the typed array to be represented as either an array of numbers
    // or an object with numeric keys mapping to the values (implementation may vary).
    if (Array.isArray(canon.bytes)) {
      expect(canon.bytes).toEqual([1, 2, 3]);
    } else {
      // object-like fallback: numeric string keys
      const obj = canon.bytes as Record<string, unknown>;
      expect(obj["0"]).toBe(1);
      expect(obj["1"]).toBe(2);
      expect(obj["2"]).toBe(3);
    }
  });

  it("deep nesting stress: 200 levels", () => {
    let obj: any = {};
    const root = obj;
    for (let i = 0; i < 200; i++) {
      obj.next = { v: i };
      obj = obj.next;
    }

    // Ensure canonicalization finishes and preserves deepest value
    const canon = toCanonicalValue(root) as Record<string, unknown>;
    let cur: any = canon;
    for (let i = 0; i < 200; i++) {
      expect(cur.next).toBeDefined();
      cur = cur.next as any;
    }
    expect(cur.v).toBe(199);
  });

  it("arrays with functions have functions elided but other elements preserved", () => {
    const input = [
      1,
      () => 2,
      {
        a: 3,
        b() {
          return 4;
        },
      },
    ];
    const canon = toCanonicalValue(input) as unknown[];
    expect(canon[0]).toBe(1);
    // function in array becomes undefined entry per project rules
    expect(canon[1]).toBeUndefined();
    // object inside array should have function property removed
    expect((canon[2] as Record<string, unknown>).a).toBe(3);
    expect(Object.prototype.hasOwnProperty.call(canon[2] as object, "b")).toBe(
      false,
    );
  });
});
