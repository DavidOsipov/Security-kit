import { describe, it, expect } from "vitest";

import { sanitizeLogMessage, secureCompareBytesOrThrow } from "../../src/utils";

describe("utils sensitive tests", () => {
  it("does not leak typed-array contents in sanitizeLogMessage", () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5]);
    const out = sanitizeLogMessage(secret);
    // The output must not contain raw byte values like '1' or '2' when
    // the input is a typed array; sanitizer should return opaque metadata.
    expect(out).not.toMatch(/1[,\s]*2[,\s]*3/);
    // The sanitizer may return either an opaque short tag like "[TypedArray]"
    // or a JSON-like metadata object that includes "__typedArray" and
    // a "byteLength" property. Accept either to remain compatible.
    const hasOpaque = out.includes("[TypedArray]");
    const hasMeta = out.includes("__typedArray");
    expect(hasOpaque || hasMeta).toBe(true);
    if (hasMeta) {
      expect(out).toContain("byteLength");
    }
  });

  it("secureCompareBytesOrThrow: success, mismatch, and typed errors", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);

    expect(secureCompareBytesOrThrow(a, b)).toBe(true);
    expect(secureCompareBytesOrThrow(a, c)).toBe(false);

    // invalid inputs should throw InvalidParameterError (but we don't import it here,
    // check that any error is thrown)
    // @ts-expect-error intentional wrong type
    expect(() => secureCompareBytesOrThrow(null, b)).toThrow();
  });
});
