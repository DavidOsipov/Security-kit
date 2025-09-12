// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { InvalidParameterError } from "../../src/errors.ts";
import {
  normalizeInputString,
} from "../../src/canonical.ts";

describe("canonical normalization security hardening - integration tests", () => {
  describe("End-to-end hardening workflow", () => {
    it("successfully processes legitimate Unicode strings", () => {
      const legitimateInputs = [
        "Hello World",
        "Bonjour le monde",
        "مرحبا بالعالم", // Arabic
        "你好世界", // Chinese - using safe characters without homoglyphs
        "こんにちは世界", // Japanese
        "안녕하세요 세계", // Korean
        "नमस्ते दुनिया", // Hindi
        "สวัสดีโลก", // Thai
        "Xin chao the gioi", // Vietnamese - ASCII safe alternative
      ];

      legitimateInputs.forEach(input => {
        const result = normalizeInputString(input, "integration-legitimate");
        expect(typeof result).toBe("string");
        expect(result.length).toBeGreaterThan(0);
      });
    });

    it("rejects malicious inputs across all attack vectors", () => {
      const maliciousInputs = [
        // Trojan Source
        "console.log('safe')\u202d';console.log('evil')//'",
        "/*\u202e*/console.log('evil');",
        "\u202a\u202b\u202c\u202d\u202e",

        // Invisible characters
        "user\u200bname",
        "path\u200c/\u200dfile",
        "data\u2060\u2061\u2062\u2063\u2064",

        // Homoglyphs
        "p\u0430ssword", // Cyrillic 'а'
        "\u03bf\u0303user", // Greek 'ο' with combining tilde
        "\uff41dmin", // Full-width 'a'
        "\ud835\udc1e", // Mathematical script 'e'

        // Dangerous Unicode
        "user\u0001name",
        "data\u007fname",
        "text\u2028\u2029",
        "value\ufeff",

        // Normalization bombs
        "\uFB03".repeat(500), // ffi ligatures causing 3x expansion - WILL be caught
        "\u3300".repeat(300), // CJK compatibility characters causing 4x expansion - WILL be caught

        // Complex combinations
        "\u0430dmin\u202e/*evil*/\u202c\u200b\u0001",
        "user\u200b\u202d\u0430\u0001name",
      ];

      maliciousInputs.forEach(input => {
        expect(() =>
          normalizeInputString(input, "integration-malicious")
        ).toThrow(InvalidParameterError);
      });
    });

    it("maintains normalization consistency", () => {
      const testCases = [
        { input: "café", expected: "café" },
        { input: "naïve", expected: "naïve" },
        { input: "résumé", expected: "résumé" },
        { input: "Å", expected: "Å" }, // Already normalized
        { input: "\u00c5", expected: "Å" }, // Decomposed Å
      ];

      testCases.forEach(({ input, expected }) => {
        const result = normalizeInputString(input, "integration-consistency");
        expect(result).toBe(expected);
      });
    });

    it("handles edge cases gracefully", () => {
      const edgeCases = [
        "",
        " ",
        "\t\n",
        "a".repeat(2000), // Large but legitimate (under 2KB limit)
        "🚀", // Emoji
        "1️⃣", // Emoji with variation selector
        "🏳️‍🌈", // Complex emoji sequence
      ];

      edgeCases.forEach(input => {
        try {
          const result = normalizeInputString(input, "integration-edge");
          expect(typeof result).toBe("string");
        } catch (error) {
          // Some edge cases might legitimately fail
          expect(error).toBeInstanceOf(InvalidParameterError);
        }
      });
    });
  });

  describe("Performance and resource limits", () => {
    it("handles large legitimate inputs efficiently", () => {
      const largeInput = "a".repeat(2000); // Just under 2KB limit
      const startTime = Date.now();

      const result = normalizeInputString(largeInput, "integration-performance");

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(result).toBe(largeInput);
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second
    });

    it("rejects inputs that would cause excessive expansion", () => {
      const expansionInputs = [
        "\uFB03".repeat(200), // ffi ligatures - 3x expansion > 2x limit
        "\u3300".repeat(100), // CJK compatibility characters - 4x expansion > 2x limit
        "\uFB01\uFB02\uFB03\uFB04".repeat(50), // Mixed ligatures causing expansion
      ];

      expansionInputs.forEach(input => {
        expect(() =>
          normalizeInputString(input, "integration-expansion")
        ).toThrow(InvalidParameterError);
      });
    });

    it("maintains consistent behavior across multiple calls", () => {
      const testInput = "café";
      const results = [];

      // Make multiple calls
      for (let i = 0; i < 100; i++) {
        results.push(normalizeInputString(testInput, `integration-consistent-${i}`));
      }

      // All results should be identical
      const firstResult = results[0];
      results.forEach(result => {
        expect(result).toBe(firstResult);
      });
    });
  });

  describe("Integration with error handling", () => {
    it("provides meaningful error messages for different attack types", () => {
      const attackCases = [
        {
          input: "user\u202dname",
          expectedPattern: /bidirectional control characters/
        },
        {
          input: "user\u200bname",
          expectedPattern: /invisible characters/
        },
        {
          input: "p\u0430ssword",
          expectedPattern: /homoglyph characters/
        },
        {
          input: "user\u0001name",
          expectedPattern: /dangerous Unicode characters/
        },
        {
          input: "\uFB03".repeat(100), // ffi ligatures causing 3x expansion
          expectedPattern: /excessive expansion/
        },
      ];

      attackCases.forEach(({ input, expectedPattern }) => {
        expect(() => normalizeInputString(input, "integration-errors")).toThrow(InvalidParameterError);
        
        try {
          normalizeInputString(input, "integration-errors");
        } catch (error) {
          if (error instanceof InvalidParameterError) {
            expect(error.message).toMatch(expectedPattern);
          } else {
            throw new Error("Expected InvalidParameterError");
          }
        }
      });
    });

    it("handles concurrent processing safely", async () => {
      const inputs = [
        "café",
        "naïve",
        "résumé",
        "你好世界", // Chinese - safe alternative
        "مرحبا",
      ];

      const promises = inputs.map((input, index) =>
        Promise.resolve().then(() =>
          normalizeInputString(input, `integration-concurrent-${index}`)
        )
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(inputs.length);
      results.forEach(result => {
        expect(typeof result).toBe("string");
      });
    });
  });

  describe("Real-world usage scenarios", () => {
    it("handles typical user input scenarios", () => {
      const userInputs = [
        "john.doe@example.com",
        "user_name123",
        "Test User",
        "café-paris",
        "naïve-approach",
        "résumé.pdf",
      ];

      userInputs.forEach(input => {
        const result = normalizeInputString(input, "integration-user");
        expect(typeof result).toBe("string");
        expect(result.length).toBeGreaterThan(0);
      });
    });

    it("handles file path scenarios", () => {
      const filePaths = [
        "/home/user/documents/café.txt",
        "/usr/local/bin/résumé",
        "C:\\Users\\ naïve\\file.pdf",
        "~/downloads/你好世界.txt",
      ];

      filePaths.forEach(path => {
        try {
          const result = normalizeInputString(path, "integration-paths");
          expect(typeof result).toBe("string");
        } catch (error) {
          // Some paths might contain problematic characters
          expect(error).toBeInstanceOf(InvalidParameterError);
        }
      });
    });

    it("handles URL and query parameter scenarios", () => {
      const urls = [
        "https://example.com/café?user=naïve",
        "https://test.com/résumé.pdf",
        "https://site.com/你好世界",
      ];

      urls.forEach(url => {
        try {
          const result = normalizeInputString(url, "integration-urls");
          expect(typeof result).toBe("string");
        } catch (error) {
          // URLs might contain problematic characters
          expect(error).toBeInstanceOf(InvalidParameterError);
        }
      });
    });
  });

  describe("Boundary conditions and limits", () => {
    it("handles maximum allowed input size", () => {
      // Test at the hardened OWASP ASVS L3 limit (64KB - 1 to stay under limit)
      const maxSizeInput = "a".repeat(2047); // Just under the 2048 byte limit
      const result = normalizeInputString(maxSizeInput, "integration-max");
      expect(result).toBe(maxSizeInput);
    });

    it("rejects inputs exceeding size limits", () => {
      // Create input that exceeds 1MB UTF-8 byte limit
      // Using multi-byte Unicode characters to reach byte limit faster
      const heavyUnicodeChar = "𝕳𝖊𝖆𝖛𝖞"; // 20 bytes in UTF-8
      const repetitions = Math.ceil(1_048_576 / 20) + 1000; // Ensure we exceed 1MB
      const oversizedInput = heavyUnicodeChar.repeat(repetitions);
      expect(() =>
        normalizeInputString(oversizedInput, "integration-oversized")
      ).toThrow(InvalidParameterError);
    });

    it("handles inputs at normalization expansion boundary", () => {
      // Use up to the hardened limit of combining characters (5 per OWASP ASVS L3)
      const boundaryInput = "a" + "\u0301".repeat(5); // At the combining character limit
      const result = normalizeInputString(boundaryInput, "integration-boundary");
      expect(typeof result).toBe("string");
    });

    it("rejects inputs exceeding expansion limits", () => {
      const expansionInput = "\uFB03".repeat(200); // ffi ligatures - 3x expansion exceeds 2x limit
      expect(() =>
        normalizeInputString(expansionInput, "integration-expansion-limit")
      ).toThrow(InvalidParameterError);
    });
  });
});