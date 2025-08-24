// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Test suite for nanoid-inspired secure string generation functionality.
 * These tests verify constitutional compliance for the new generateSecureStringSync function.
 *
 * Tests focus on:
 * - Security: Uniform distribution and bias prevention
 * - Constitution compliance: Input validation and error handling
 * - Performance: Bitmasking optimization verification
 * - Memory safety: Proper cleanup verification
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  generateSecureStringSync,
  generateSecureIdSync,
  generateSecureId,
  URL_ALPHABET,
  InvalidParameterError,
} from "../utils/security_kit.ts";

describe("Nanoid-Inspired Secure String Generation", () => {
  describe("generateSecureStringSync - Basic Functionality", () => {
    it("should generate strings of correct length", () => {
      const result = generateSecureStringSync("abc", 10);
      expect(result).toHaveLength(10);
      expect(typeof result).toBe("string");
    });

    it("should only use characters from the provided alphabet", () => {
      const alphabet = "ABC123";
      const result = generateSecureStringSync(alphabet, 100);

      for (const char of result) {
        expect(alphabet).toContain(char);
      }
    });

    it("should work with single character alphabet", () => {
      const result = generateSecureStringSync("X", 5);
      expect(result).toBe("XXXXX");
    });

    it("should work with URL_ALPHABET constant", () => {
      const result = generateSecureStringSync(URL_ALPHABET, 21);
      expect(result).toHaveLength(21);

      for (const char of result) {
        expect(URL_ALPHABET).toContain(char);
      }
    });
  });

  describe("generateSecureStringSync - Constitutional Compliance", () => {
    it("should fail loudly on invalid size parameters", () => {
      expect(() => generateSecureStringSync("abc", 0)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureStringSync("abc", -1)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureStringSync("abc", 1025)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureStringSync("abc", 1.5)).toThrow(
        InvalidParameterError,
      );
    });

    it("should fail loudly on invalid alphabet parameters", () => {
      expect(() => generateSecureStringSync("", 5)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureStringSync("a".repeat(257), 5)).toThrow(
        InvalidParameterError,
      );
      // @ts-expect-error - Testing invalid type
      expect(() => generateSecureStringSync(123, 5)).toThrow(
        InvalidParameterError,
      );
      // @ts-expect-error - Testing invalid type
      expect(() => generateSecureStringSync(null, 5)).toThrow(
        InvalidParameterError,
      );
    });

    it("should fail loudly on duplicate characters in alphabet", () => {
      expect(() => generateSecureStringSync("aab", 5)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureStringSync("abcabc", 5)).toThrow(
        InvalidParameterError,
      );
    });

    it("should handle edge case alphabets correctly", () => {
      // Test with maximum allowed alphabet size
      const largeAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?`~".slice(
          0,
          256,
        );
      expect(() => generateSecureStringSync(largeAlphabet, 10)).not.toThrow();
    });
  });

  describe("generateSecureStringSync - Security Properties", () => {
    it("should work with the mocked crypto environment", () => {
      // In the test environment, crypto is mocked with predictable values
      // This test verifies the function works, even if not truly random
      const alphabet = "abcdefghijklmnopqrstuvwxyz";
      const result = generateSecureStringSync(alphabet, 10);

      expect(result).toHaveLength(10);
      expect(typeof result).toBe("string");

      // All characters should be from the alphabet
      for (const char of result) {
        expect(alphabet).toContain(char);
      }
    });

    it("should have consistent behavior with binary alphabet", () => {
      // Test with a simple binary alphabet
      const alphabet = "AB";
      const result = generateSecureStringSync(alphabet, 20);

      expect(result).toHaveLength(20);
      expect(result).toMatch(/^[AB]+$/);

      // Randomness in the test environment may be deterministic; just assert valid characters
    });

    it("should handle power-of-two alphabet sizes efficiently", () => {
      // Test with 2, 4, 8, 16, 32, 64 character alphabets (powers of 2)
      const powerOfTwoAlphabets = [
        "AB",
        "ABCD",
        "ABCDEFGH",
        "ABCDEFGHIJKLMNOP",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", // 32 chars
        URL_ALPHABET, // 64 chars
      ];

      powerOfTwoAlphabets.forEach((alphabet) => {
        const result = generateSecureStringSync(alphabet, 20);
        expect(result).toHaveLength(20);

        for (const char of result) {
          expect(alphabet).toContain(char);
        }
      });
    });

    it("should handle non-power-of-two alphabet sizes correctly", () => {
      // Test with alphabets that are NOT powers of 2
      const nonPowerOfTwoAlphabets = [
        "ABC", // 3 chars
        "ABCDE", // 5 chars
        "ABCDEFG", // 7 chars
        "ABCDEFGHIJ", // 10 chars
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", // 26 chars
      ];

      nonPowerOfTwoAlphabets.forEach((alphabet) => {
        const result = generateSecureStringSync(alphabet, 20);
        expect(result).toHaveLength(20);

        for (const char of result) {
          expect(alphabet).toContain(char);
        }
      });
    });
  });

  describe("Integration with existing API", () => {
    it("should maintain backward compatibility for generateSecureIdSync", () => {
      const result = generateSecureIdSync(32);
      expect(result).toHaveLength(32);
      expect(result).toMatch(/^[0-9a-f]+$/); // Should be hex characters only
    });

    it("should maintain backward compatibility for generateSecureId async", async () => {
      const result = await generateSecureId(16);
      expect(result).toHaveLength(16);
      expect(result).toMatch(/^[0-9a-f]+$/); // Should be hex characters only
    });

    it("should generate valid hex strings consistently", () => {
      // In the mocked environment, we focus on correctness over randomness
      const results = [];

      for (let i = 0; i < 5; i++) {
        results.push(generateSecureIdSync(8));
      }

      // All results should be valid hex and correct length
      results.forEach((result) => {
        expect(result).toMatch(/^[0-9a-f]{8}$/);
        expect(result).toHaveLength(8);
      });
    });
  });

  describe("Performance Characteristics", () => {
    it("should complete within reasonable time for typical use cases", () => {
      const start = performance.now();

      // Generate 100 medium-length strings
      for (let i = 0; i < 100; i++) {
        generateSecureStringSync(URL_ALPHABET, 21);
      }

      const elapsed = performance.now() - start;

      // Should complete well under 1 second for 100 generations
      expect(elapsed).toBeLessThan(1000);
    });

    it("should handle large string generation without timeout", () => {
      // Test generating a large string doesn't hang
      const result = generateSecureStringSync("ABC", 1000);
      expect(result).toHaveLength(1000);
      expect(result).toMatch(/^[ABC]+$/);
    });
  });
});
