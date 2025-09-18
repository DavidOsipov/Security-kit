import { describe, it, expect } from "vitest";
import { normalizeInputString } from "../../src/canonical.ts";
import { InvalidParameterError, UnicodeErrorCode } from "../../src/errors.ts";

function extractCode(message: string): string | undefined {
  const m = message.match(/\[code=(ERR_UNICODE_[A-Z_]+)\]/);
  return m ? m[1] : undefined;
}

describe("normalizeInputString surrogate validation", () => {
  it("rejects lone high surrogate", () => {
    try {
      normalizeInputString("\uD83D", "test");
      throw new Error("Expected rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(InvalidParameterError);
      const code = extractCode((e as Error).message);
      expect(code).toBe(UnicodeErrorCode.Surrogate);
    }
  });

  it("rejects unpaired low surrogate", () => {
    try {
      normalizeInputString("\uDC00", "test");
      throw new Error("Expected rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(InvalidParameterError);
      const code = extractCode((e as Error).message);
      expect(code).toBe(UnicodeErrorCode.Surrogate);
    }
  });

  it("accepts valid surrogate pair", () => {
    // 😀 U+1F600 surrogate pair D83D DE00
    const ok = normalizeInputString("😀", "emoji");
    expect(ok).toBe("😀");
  });
});

describe("normalizeInputString structural introduction samples limit", () => {
  it("rejects when NFKC introduces a structural delimiter (fullwidth colon)", () => {
    // Fullwidth colon U+FF1A normalizes to ASCII ':' which is a structural risk char.
    const fullwidthColon = "："; // U+FF1A
    if (fullwidthColon.normalize("NFKC") === ":") {
      try {
        normalizeInputString(fullwidthColon, "struct");
        throw new Error("Expected structural introduction rejection");
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidParameterError);
        const code = extractCode((e as Error).message);
        expect(code).toBe(UnicodeErrorCode.Structural);
      }
    } else {
      // Environment anomaly: if normalization did not map (unlikely), assert pass-through
      const result = normalizeInputString(fullwidthColon, "struct-env");
      expect(result).toBe(fullwidthColon);
    }
  });
});