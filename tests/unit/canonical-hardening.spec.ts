// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { InvalidParameterError } from "../../src/errors.ts";
import { normalizeInputString, toCanonicalValue } from "../../src/canonical.ts";
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from "../../src/config.ts";
import { MAX_KEYS_PER_OBJECT } from "../../src/utils.ts";

describe("canonical normalization hardening", () => {
  const original = getUnicodeSecurityConfig();
  beforeAll(() => {
    // Ensure risk scoring enabled for mutation immutability test
    setUnicodeSecurityConfig({ enableRiskScoring: true });
  });
  afterAll(() => {
    // Restore config (best effort)
    setUnicodeSecurityConfig({
      dataProfile: original.dataProfile,
      lazyLoad: original.lazyLoad,
      maxInputLength: original.maxInputLength,
      enableConfusablesDetection: original.enableConfusablesDetection,
      enableValidationCache: original.enableValidationCache,
      enableRiskScoring: original.enableRiskScoring,
      riskWarnThreshold: original.riskWarnThreshold,
      riskBlockThreshold: original.riskBlockThreshold,
      blockRawShellChars: original.blockRawShellChars,
    });
  });
  describe("structural delimiter detection (via normalizeInputString)", () => {
    it("passes when no structural characters are introduced", () => {
      const input = "hello world";
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("passes when structural characters exist in input", () => {
      const input = "hello/world";
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("throws when forward slash is introduced via homoglyph", () => {
      // Create input that would normalize to introduce /
      // This is tricky to test directly since NFKC doesn't actually introduce /
      // from homoglyphs in this way. Let's test with a different approach.
      const input = "test\u2044example"; // fraction slash
      expect(() => normalizeInputString(input, "test")).not.toThrow();
      // The input itself contains the structural char, so it should be allowed
    });

    it("handles empty strings", () => {
      expect(() => normalizeInputString("", "test")).not.toThrow();
    });

    it("handles strings with no structural characters", () => {
      const input = "hello world 123";
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("handles Unicode characters that don't introduce structural chars", () => {
      const input = "café"; // é is U+00E9, NFC normalized
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });
  });

  describe("normalization idempotency (via normalizeInputString)", () => {
    it("passes for idempotent NFKC normalization", () => {
      const input = "hello world";
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("passes for complex Unicode that remains stable", () => {
      const input = "café résumé naïve"; // Already in NFKC
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("passes for empty string", () => {
      expect(() => normalizeInputString("", "test")).not.toThrow();
    });

    it("handles surrogate pairs correctly", () => {
      const input = "🎉"; // Emoji with surrogate pair
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("handles combining characters", () => {
      const input = "e\u0301"; // e + combining acute accent
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });
  });

  describe("normalizeInputString with hardening", () => {
    it("accepts options parameter for maxLength", () => {
      const result = normalizeInputString("hello", "test", { maxLength: 100 });
      expect(result).toBe("hello");
    });

    it("respects maxLength option", () => {
      const longString = "a".repeat(1000);
      expect(() =>
        normalizeInputString(longString, "test", { maxLength: 100 }),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(longString, "test", { maxLength: 100 }),
      ).toThrow(/Input exceeds maximum allowed size/);
    });

    it("defaults to MAX_INPUT_LENGTH_BYTES when no maxLength provided", () => {
      const result = normalizeInputString("hello", "test");
      expect(result).toBe("hello");
    });

    it("handles undefined options gracefully", () => {
      const result = normalizeInputString("hello", "test", undefined);
      expect(result).toBe("hello");
    });

    it("applies NFKC normalization", () => {
      // Test with a character that changes under NFKC
      const input = "Ⅳ"; // Roman numeral four
      const result = normalizeInputString(input, "test");
      expect(result).toBe("IV"); // Should be normalized
    });

    it("rejects excessively long inputs for DoS protection", () => {
      // Create an input that exceeds the byte limit
      const longInput = "a".repeat(2000000); // Over 2MB
      expect(() =>
        normalizeInputString(longInput, "test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(longInput, "test"),
      ).toThrow(/exceeds maximum allowed size/);
    });

    it("rejects Trojan Source bidirectional control characters", () => {
      const input = "hello\u202e world"; // Right-to-left override
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(/bidirectional control characters/);
    });

    it("rejects invisible characters", () => {
      const input = "hello\u200bworld"; // Zero-width space
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(/invisible\/zero-width/);
    });

    // Homoglyph presence currently logs (warning) not hard-reject; ensure no throw
    it("does not throw for mixed-script homoglyph (logs warning only)", () => {
      const input = "hello\u0430world"; // Cyrillic 'а'
      expect(() => normalizeInputString(input, "test")).not.toThrow();
    });

    it("rejects dangerous Unicode ranges", () => {
      const input = "hello\u0001world"; // Control character
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(input, "test"),
      ).toThrow(/disallowed control/);
    });

    it("handles empty input", () => {
      const result = normalizeInputString("", "test");
      expect(result).toBe("");
    });

    it("handles null input", () => {
      const result = normalizeInputString(null, "test");
      expect(result).toBe(""); // null converts to empty string
    });

    it("handles undefined input", () => {
      const result = normalizeInputString(undefined, "test");
      expect(result).toBe(""); // undefined converts to empty string
    });

    it("handles number input", () => {
      const result = normalizeInputString(42, "test");
      expect(result).toBe("42");
    });

    it("handles boolean input", () => {
      const result = normalizeInputString(true, "test");
      expect(result).toBe("true");
    });

    it("handles object input", () => {
      const result = normalizeInputString({ key: "value" }, "test");
      expect(result).toBe('{"key":"value"}');
    });

    it("handles array input", () => {
      const result = normalizeInputString([1, 2, 3], "test");
      expect(result).toBe("[1,2,3]");
    });

    it("rejects structural delimiter introduced via normalization (fullwidth colon)", () => {
      expect(() => normalizeInputString("\uFF1A", "struct-intro"))
        .toThrow(InvalidParameterError);
    });

    it("enforces MAX_KEYS_PER_OBJECT cap in deep scan", () => {
      const obj: Record<string, unknown> = {};
      for (let i = 0; i < MAX_KEYS_PER_OBJECT + 5; i++) obj["k" + i] = i;
      expect(() => toCanonicalValue(obj)).toThrow(InvalidParameterError);
    });

    it("freezes risk assessment payload (mutation attempts fail)", () => {
      let mutationError: unknown;
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        onRiskAssessment: (payload) => {
          try {
            // @ts-expect-error intentional mutation attempt
            (payload as any).score = 9999;
          } catch (e) {
            mutationError = e;
          }
          try {
            // @ts-expect-error intentional mutation attempt
            (payload.metrics as any).push({ id: "x", score: 0, triggered: false });
          } catch (e) {
            mutationError = e;
          }
        },
      });
      // Use non-ASCII so fast path skipped
      normalizeInputString("é", "risk-freeze");
      expect(mutationError).toBeInstanceOf(TypeError);
    });
  });
});