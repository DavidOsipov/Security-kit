import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { safeStableStringify } from "../../src/canonical";
import { isForbiddenKey } from "../../src/constants";

// Helper to strip forbidden keys recursively
function stripForbidden(input: unknown): unknown {
  if (Array.isArray(input)) return input.map(stripForbidden);
  if (input && typeof input === "object") {
    const result: Record<string, unknown> = Object.create(null);
    for (const k of Object.keys(input as Record<string, unknown>)) {
      if (isForbiddenKey(k)) continue;
      result[k] = stripForbidden((input as Record<string, unknown>)[k]);
    }
    return result;
  }
  return input;
}

describe("safeStableStringify - fuzz/property based", () => {
  it("does not crash and is deterministic across runs for complex nested structures", async () => {
    const arb = fc.letrec((tie) => ({
      obj: fc.dictionary(
        fc.string({ minLength: 1, maxLength: 8 }),
        tie("value"),
        { maxKeys: 6 },
      ),
      arr: fc.array(tie("value"), { maxLength: 8 }),
      value: fc.oneof(
        fc.string({ maxLength: 16 }),
        fc.boolean(),
        fc.float({ noNaN: true, noDefaultInfinity: true }),
        fc.constant(null),
        fc.oneof(
          fc.constant(undefined),
          fc.nat({ max: 10 }).map((n) => (n % 3 === 0 ? undefined : n)),
        ),
        tie("obj"),
        tie("arr"),
      ),
    })).value;

    await fc.assert(
      fc.asyncProperty(arb, async (data) => {
        const s1 = safeStableStringify(data);
        const s2 = safeStableStringify(data);
        expect(s1).toBe(s2);
      }),
      { numRuns: 100 },
    );
  });

  it("ignores proto-pollution keys and matches the purified variant", async () => {
    const pollutedArb = fc.letrec((tie) => ({
      obj: fc.dictionary(
        fc.oneof(
          fc.constant("__proto__"),
          fc.constant("prototype"),
          fc.constant("constructor"),
          fc.string({ minLength: 1, maxLength: 8 }),
        ),
        tie("value"),
        { maxKeys: 6 },
      ),
      arr: fc.array(tie("value"), { maxLength: 6 }),
      value: fc.oneof(
        fc.string({ maxLength: 16 }),
        fc.boolean(),
        fc.float({ noNaN: true, noDefaultInfinity: true }),
        fc.constant(null),
        tie("obj"),
        tie("arr"),
      ),
    })).value;

    await fc.assert(
      fc.asyncProperty(pollutedArb, async (data) => {
        const sPolluted = safeStableStringify(data);
        const sClean = safeStableStringify(stripForbidden(data));
        expect(sPolluted).toBe(sClean);
      }),
      { numRuns: 60 },
    );
  });
});
