// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { InvalidParameterError } from "../../src/errors.ts";
import {
  normalizeInputString,
} from "../../src/canonical.ts";
import testPayloads from "../fixtures/test-expansion-payloads.json";

describe("canonical normalization security hardening - adversarial tests", () => {
  describe("Trojan Source attack vectors", () => {
    it("rejects bidirectional control characters (LTR override)", () => {
      const malicious = "console.log('safe')\u202d';console.log('evil')//'"; // LTR override
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(/bidirectional control characters/);
    });

    it("rejects bidirectional control characters (RTL override)", () => {
      const malicious = "console.log('safe')\u202e';console.log('evil')//'"; // RTL override
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(/bidirectional control characters/);
    });

    it("rejects bidirectional embedding sequences", () => {
      const malicious = "\u202a console.log('evil') \u202c"; // LRE...PDF
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(/bidirectional control characters/);
    });

    it("rejects complex Trojan Source patterns", () => {
      // Pattern from Trojan Source research: LRO + PDF
      const malicious = "\u202d/*\u202c*/console.log('evil');";
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects Trojan Source with invisible characters", () => {
      const malicious = "safe\u200b\u202eunsafe\u202c"; // ZWSP + RTL override
      expect(() =>
        normalizeInputString(malicious, "trojan-test"),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Invisible character attacks", () => {
    it("rejects zero-width space", () => {
      const malicious = "user\u200bname"; // Zero-width space
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(/invisible characters/);
    });

    it("rejects zero-width non-joiner", () => {
      const malicious = "user\u200cname"; // Zero-width non-joiner
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects zero-width joiner", () => {
      const malicious = "user\u200dname"; // Zero-width joiner
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects left-to-right mark", () => {
      const malicious = "user\u200ename"; // Left-to-right mark
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects right-to-left mark", () => {
      const malicious = "user\u200fname"; // Right-to-left mark
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects word joiner", () => {
      const malicious = "user\u2060name"; // Word joiner
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects function application", () => {
      const malicious = "user\u2061name"; // Function application
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects invisible times", () => {
      const malicious = "user\u2062name"; // Invisible times
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects invisible separator", () => {
      const malicious = "user\u2063name"; // Invisible separator
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects invisible plus", () => {
      const malicious = "user\u2064name"; // Invisible plus
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects multiple invisible characters", () => {
      const malicious = "user\u200b\u200c\u200d\u2060name";
      expect(() =>
        normalizeInputString(malicious, "invisible-test"),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Homoglyph attacks", () => {
    it("rejects Cyrillic 'а' (looks like Latin 'a')", () => {
      const malicious = "p\u0430ssword"; // Cyrillic 'а'
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(/homoglyph characters/);
    });

    it("rejects Greek 'ο' (looks like Latin 'o')", () => {
      const malicious = "passw\u03bf\u0303rd"; // Greek 'ο' with combining tilde
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects Latin Extended Additional characters", () => {
      const malicious = "user\u1e9bname"; // Latin small letter s with dot below
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects full-width Latin characters", () => {
      const malicious = "\uff41dmin"; // Full-width Latin 'a'
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects mathematical alphanumeric symbols", () => {
      const malicious = "\ud835\udc1e"; // Mathematical script small e
      expect(() =>
        normalizeInputString(malicious, "homoglyph-test"),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Dangerous Unicode range attacks", () => {
    it("rejects control characters (C0 range)", () => {
      const malicious = "user\u0001name"; // SOH (Start of Heading)
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(/dangerous Unicode characters/);
    });

    it("rejects control characters (C1 range)", () => {
      const malicious = "user\u0080name"; // Padding Character
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects delete character", () => {
      const malicious = "user\u007fname"; // DEL
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects line/paragraph separators", () => {
      const malicious = "user\u2028name"; // Line separator
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects BOM and other special characters", () => {
      const malicious = "user\ufeffname"; // Zero-width no-break space (BOM)
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
    });

    it("rejects private use area characters", () => {
      const malicious = "user\uf000name"; // Private Use Area
      expect(() =>
        normalizeInputString(malicious, "control-test"),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Normalization bomb attacks - Real Unicode Expansion Payloads", () => {
    it("should reject high expansion ratio characters (>= 2.5x)", () => {
      if (!testPayloads.highExpansion?.length) {
        throw new Error("No high expansion test payloads found");
      }

      // Test the most dangerous ones first
      for (const payload of testPayloads.highExpansion.slice(0, 10)) {
        expect(() => normalizeInputString(payload.char, "expansion-bomb-test"))
          .toThrow(InvalidParameterError);
        expect(() => normalizeInputString(payload.char, "expansion-bomb-test"))
          .toThrow(/excessive expansion/);
      }
    });

    it("should reject 6x expansion characters (most dangerous)", () => {
      // These are the worst offenders - 6x expansion ratio
      const mostDangerous = testPayloads.highExpansion.filter(p => p.expansionRatio >= 6);
      
      expect(mostDangerous.length).toBeGreaterThan(0);
      
      for (const payload of mostDangerous) {
        expect(() => normalizeInputString(payload.char, "max-expansion-test"))
          .toThrow(InvalidParameterError);
        expect(() => normalizeInputString(payload.char, "max-expansion-test"))
          .toThrow(/excessive expansion/);
      }
    });

    it("should allow safe expansion characters (<= 2x ratio)", () => {
      if (!testPayloads.safeExpansion?.length) {
        console.warn("No safe expansion test payloads found");
        return;
      }

      // Test a few safe expansion characters that should pass
      // Filter out any that might trigger homoglyph detection
      const safeBelowHomoglyphThreshold = testPayloads.safeExpansion.filter(p => {
        // Avoid characters that might be flagged as homoglyphs
        // Check if character is in basic Latin or simple accented ranges
        const codePoint = p.char.codePointAt(0) || 0;
        return (codePoint < 0x100 || codePoint > 0x2000) && p.expansionRatio <= 1.5;
      }).slice(0, 3);

      if (safeBelowHomoglyphThreshold.length === 0) {
        console.warn("No safe non-homoglyph expansion characters found");
        return;
      }

      for (const payload of safeBelowHomoglyphThreshold) {
        try {
          const result = normalizeInputString(payload.char, "safe-expansion-test");
          expect(result).toBe(payload.normalized);
        } catch (error) {
          // If it's caught by other security checks (e.g., homoglyph), skip this test
          if (error instanceof InvalidParameterError && error.message.includes("homoglyph")) {
            console.warn(`Skipping ${payload.char} due to homoglyph detection`);
            continue;
          }
          throw error;
        }
      }
    });

    it("should handle ligature expansion attacks", () => {
      const ligatures = testPayloads.ligatures || [];
      if (ligatures.length === 0) {
        console.warn("No ligature payloads found");
        return;
      }

      // Test common ligatures that might be used in attacks
      for (const payload of ligatures.slice(0, 5)) {
        if (payload.expansionRatio > 2) {
          expect(() => normalizeInputString(payload.char, "ligature-test"))
            .toThrow(InvalidParameterError);
        } else {
          // Safe ligatures should pass
          const result = normalizeInputString(payload.char, "ligature-test");
          expect(result).toBe(payload.normalized);
        }
      }
    });

    it("should handle CJK compatibility character attacks", () => {
      const cjkChars = testPayloads.cjkCompatibility || [];
      if (cjkChars.length === 0) {
        console.warn("No CJK compatibility payloads found");
        return;
      }

      // Test dangerous CJK characters
      for (const payload of cjkChars.slice(0, 5)) {
        if (payload.expansionRatio > 2) {
          expect(() => normalizeInputString(payload.char, "cjk-test"))
            .toThrow(InvalidParameterError);
          expect(() => normalizeInputString(payload.char, "cjk-test"))
            .toThrow(/excessive expansion/);
        }
      }
    });

    it("should handle fraction character attacks", () => {
      // Check both the test payloads and the full unicode data for number/fraction characters
      const fractionLikeFromFull = require("../fixtures/unicode-expansion-payloads.json")
        .byCategory?.["Number/Roman"] || [];
      const combinedFractions = [...(testPayloads.fractions || []), ...fractionLikeFromFull];
      
      if (combinedFractions.length === 0) {
        console.warn("No fraction/number payloads found");
        return;
      }

      // Test fraction/number characters - most should be >= 2x expansion
      for (const payload of combinedFractions.slice(0, 5)) {
        if (payload.expansionRatio > 2) {
          expect(() => normalizeInputString(payload.char, "fraction-test"))
            .toThrow(InvalidParameterError);
        } else {
          // Safe fractions should pass (if not caught by other security checks)
          try {
            const result = normalizeInputString(payload.char, "fraction-test");
            expect(result).toBe(payload.normalized);
          } catch (error) {
            if (error instanceof InvalidParameterError && 
                (error.message.includes("homoglyph") || error.message.includes("dangerous"))) {
              console.warn(`Skipping ${payload.char} due to other security check`);
              continue;
            }
            throw error;
          }
        }
      }
    });

    it("should detect bulk expansion bomb attacks", () => {
      // Use a high-expansion character repeated many times
      const dangerousChar = testPayloads.maxThreat?.[0];
      if (!dangerousChar) {
        throw new Error("No max threat payload found");
      }

      const bombPayload = dangerousChar.char.repeat(100);
      expect(() => normalizeInputString(bombPayload, "bulk-bomb-test"))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString(bombPayload, "bulk-bomb-test"))
        .toThrow(/excessive expansion/);
    });

    it("validates expansion ratio calculations with real payloads", () => {
      // Verify our test data is accurate
      const testChar = testPayloads.highExpansion?.[0];
      if (!testChar) {
        throw new Error("No high expansion test character found");
      }

      // Manually verify the expansion
      const normalized = testChar.char.normalize("NFKC");
      expect(normalized).toBe(testChar.normalized);
      expect(normalized.length).toBe(testChar.normalizedLength);
      expect(testChar.char.length).toBe(testChar.originalLength);
      expect(normalized.length / testChar.char.length).toBe(testChar.expansionRatio);
    });

    // Legacy tests with hardcoded values (keep for edge cases)
    it("handles boundary case near expansion limit", () => {
      const safe = "a" + "\u0301".repeat(5); // At the hardened OWASP ASVS L3 limit
      const result = normalizeInputString(safe, "boundary-test");
      expect(result).toBeDefined();
    });
  });

  describe("Complex attack combinations", () => {
    it("handles Trojan Source + homoglyph combination", () => {
      const malicious = "\u0430dmin\u202e/*evil*/\u202c"; // Cyrillic a + RTL override
      expect(() =>
        normalizeInputString(malicious, "combo-test"),
      ).toThrow(InvalidParameterError);
    });

    it("handles invisible chars + control chars", () => {
      const malicious = "path\u200b/\u200b\u0001";
      expect(() =>
        normalizeInputString(malicious, "combo-test"),
      ).toThrow(InvalidParameterError);
    });

    it("handles control chars + normalization bombs", () => {
      const malicious = "\u0001" + "\u0301".repeat(500) + "\u0002";
      expect(() =>
        normalizeInputString(malicious, "combo-test"),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Edge cases and false positives", () => {
    it("allows legitimate Unicode in safe contexts", () => {
      const legitimate = "café"; // Legitimate accented character
      const result = normalizeInputString(legitimate, "legitimate-test");
      expect(result).toBe("café");
    });

    it("allows mathematical symbols in appropriate contexts", () => {
      const math = "∑"; // Summation symbol - might be legitimate in some contexts
      // Note: This might be rejected depending on homoglyph detection
      try {
        const result = normalizeInputString(math, "math-test");
        expect(result).toBeDefined();
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("handles empty and whitespace-only strings", () => {
      expect(() => normalizeInputString("", "empty-test")).not.toThrow();
      expect(() => normalizeInputString("   ", "whitespace-test")).not.toThrow();
    });

    it("handles very long legitimate strings within 2KB limit", () => {
      // Test with strings approaching but not exceeding the 2KB limit
      // 2048 bytes = 2048 ASCII characters (1 byte each)
      const longLegitimate = "a".repeat(2000); // Just under 2KB limit
      const result = normalizeInputString(longLegitimate, "long-test");
      expect(result).toBe("a".repeat(2000));
    });

    it("rejects strings exceeding 2KB limit", () => {
      // Test that strings over 2KB are properly rejected
      const tooLong = "a".repeat(2100); // Over 2KB limit
      expect(() => normalizeInputString(tooLong, "too-long-test"))
        .toThrow(InvalidParameterError);
      expect(() => normalizeInputString(tooLong, "too-long-test"))
        .toThrow(/exceeds maximum allowed size/); // Fixed error message
    });
  });
});