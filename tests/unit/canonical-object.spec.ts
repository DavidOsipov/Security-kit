import { describe, it, expect } from "vitest";
import { toCanonicalValue, safeStableStringify, hasCircularSentinel } from "../../src/canonical.ts";
import { InvalidParameterError } from "../../src/errors.ts";

describe("canonical-object", () => {
  it("removes forbidden keys and preserves order lexicographically", () => {
    const input = { b: 2, a: 1, __proto__: 5 } as Record<string, unknown>;
    const canon = toCanonicalValue(input) as Record<string, unknown>;
    const json = safeStableStringify(canon);
    expect(json).toBe("{\"a\":1,\"b\":2}");
  });

  it("rejects BigInt nested", () => {
    const obj = { a: { b: 1n } } as unknown;
    expect(() => toCanonicalValue(obj)).toThrow(InvalidParameterError);
  });

  it("marks circular references with sentinel", () => {
    const o: Record<string, unknown> = { a: 1 };
    // eslint-disable-next-line @typescript-eslint/consistent-type-assertions -- intentional self reference construction
    (o as Record<string, unknown> & { self?: unknown }).self = o;
    const canon = toCanonicalValue(o);
    expect(hasCircularSentinel(canon)).toBe(true);
    const json = safeStableStringify(canon);
    expect(json).toContain("__circular");
  });
});
