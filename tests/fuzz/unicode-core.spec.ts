import { describe, it, expect } from "vitest";
import { normalizeInputString } from "../../src/canonical.ts";
import { InvalidParameterError, UnicodeErrorCode } from "../../src/errors.ts";

function codeOf(e: unknown): string | undefined {
  if (!(e instanceof Error)) return undefined;
  const m = e.message.match(/\[code=(ERR_UNICODE_[A-Z_]+)\]/);
  return m ? m[1] : undefined;
}

describe("unicode-core small fuzz (fast)", () => {
  const cases = [
    { raw: "abc", expectSame: true },
    { raw: "ＡＢＣ", expectSame: false }, // fullwidth letters
    { raw: "\u202Eabc", expectError: UnicodeErrorCode.Bidi },
    { raw: "a\u200Db", expectError: UnicodeErrorCode.Invisible },
  // Variation selector FE0F may also be flagged under INVISIBLE depending on ordering.
  { raw: "a\uFE0Fb", expectErrorOneOf: [UnicodeErrorCode.Variation, UnicodeErrorCode.Invisible] },
  ];
  for (const c of cases) {
    it(`case: ${c.raw.replace(/\n/g, "\\n")}`, () => {
      try {
        const out = normalizeInputString(c.raw, "test");
        if (c.expectError) throw new Error("Expected error");
        if (c.expectSame) expect(out).toBe(c.raw.normalize("NFKC"));
      } catch (e) {
        if (c.expectErrorOneOf) {
          expect(e).toBeInstanceOf(InvalidParameterError);
          const code = codeOf(e);
            expect(c.expectErrorOneOf).toContain(code);
        } else if (c.expectError) {
          expect(e).toBeInstanceOf(InvalidParameterError);
          expect(codeOf(e)).toBe(c.expectError);
        } else {
          throw e; // unexpected
        }
      }
    });
  }
});
