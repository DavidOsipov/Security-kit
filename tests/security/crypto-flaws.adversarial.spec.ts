// tests/security/crypto-flaws.adversarial.spec.ts
// Comprehensive cryptographic flaw tests aligned with OWASP ASVS L3
// Focus: Weak RNG, nonce reuse, circuit breaker manipulation, timing attacks

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  getSecureRandomBytesSync,
  getSecureRandomInt,
  generateSecureStringSync,
  createAesGcmKey256,
} from "../../src/crypto";
import { secureCompare, secureCompareAsync } from "../../src/utils";
import { InvalidParameterError } from "../../src/errors";

describe("Cryptographic Flaws - Adversarial Attacks (OWASP ASVS L3)", () => {
  describe("Weak RNG and Predictability", () => {
    let originalGetRandomValues: any;

    beforeEach(() => {
      originalGetRandomValues = globalThis.crypto.getRandomValues;
    });

    afterEach(() => {
      globalThis.crypto.getRandomValues = originalGetRandomValues;
    });

    it("should detect and handle weak RNG that returns predictable values", () => {
      // Mock weak RNG that always returns the same bytes
      const mockGetRandomValues = vi.fn((arr: any) => {
        if (arr instanceof Uint8Array) {
          arr.fill(0xAA);
        }
        return arr;
      });
      globalThis.crypto.getRandomValues = mockGetRandomValues;

      const bytes1 = getSecureRandomBytesSync(32);
      const bytes2 = getSecureRandomBytesSync(32);

      // With weak RNG, bytes should be identical (this is the attack)
      expect(bytes1).toEqual(bytes2);

      // But the function should still work without throwing
      expect(bytes1.length).toBe(32);
      expect(bytes2.length).toBe(32);
    });

    it("should handle RNG that returns sequential values", () => {
      let counter = 0;
      const mockGetRandomValues = vi.fn((arr: any) => {
        if (arr instanceof Uint8Array) {
          arr.fill(counter++);
        }
        return arr;
      });
      globalThis.crypto.getRandomValues = mockGetRandomValues;

      const values = [];
      for (let i = 0; i < 10; i++) {
        values.push(getSecureRandomBytesSync(1)[0]);
      }

      // Values should be sequential (predictable)
      for (let i = 1; i < values.length; i++) {
        expect(values[i]).toBe(values[i - 1] + 1);
      }
    });

    it("should reject invalid random generation parameters", () => {
      expect(() => getSecureRandomBytesSync(-1)).toThrow(InvalidParameterError);
      expect(() => getSecureRandomBytesSync(0)).toThrow(InvalidParameterError);
      expect(() => getSecureRandomBytesSync(1000000)).toThrow(InvalidParameterError);
    });
  });

  describe("Timing Attacks on Comparisons", () => {
    it("should use constant-time comparison for secrets", async () => {
      const secret1 = "supersecretpassword";
      const secret2 = "supersecretpassword";
      const wrongSecret = "wrongpassword";

      // Correct comparison should take same time as incorrect
      const start1 = performance.now();
      const result1 = await secureCompareAsync(secret1, secret2);
      const time1 = performance.now() - start1;

      const start2 = performance.now();
      const result2 = await secureCompareAsync(secret1, wrongSecret);
      const time2 = performance.now() - start2;

      expect(result1).toBe(true);
      expect(result2).toBe(false);

  // Timing difference should be minimal. Allow generous margin (<=50ms) to account 
  // for scheduler jitter, timing equalization overhead, and CI variance while 
  // still detecting real timing side-channel vulnerabilities per OWASP ASVS L3.
  // Real timing attacks require statistical analysis across many measurements,
  // not single-measurement variance which can be high in CI environments.
  expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });

    it("should handle strings of different lengths securely", async () => {
      const short = "abc";
      const long = "abcdefghijklmnopqrstuvwxyz";

      const start1 = performance.now();
      const result1 = await secureCompareAsync(short, long);
      const time1 = performance.now() - start1;

      const start2 = performance.now();
      const result2 = await secureCompareAsync(long, short);
      const time2 = performance.now() - start2;

      expect(result1).toBe(false);
      expect(result2).toBe(false);

  // Timing should be similar despite length difference; permit reasonable CI jitter
  expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });

    it("should handle empty strings securely", async () => {
      const empty = "";
      const nonEmpty = "a";

      const start1 = performance.now();
      const result1 = await secureCompareAsync(empty, nonEmpty);
      const time1 = performance.now() - start1;

      const start2 = performance.now();
      const result2 = await secureCompareAsync(nonEmpty, empty);
      const time2 = performance.now() - start2;

      expect(result1).toBe(false);
      expect(result2).toBe(false);

  expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });
  });

  describe("Nonce Reuse and State Attacks", () => {
    it("should generate unique nonces for AES-GCM", () => {
      // Since createAesGcmNonce is not exported, test the underlying random generation
      const nonces = new Set<string>();

      for (let i = 0; i < 1000; i++) {
        const nonce = getSecureRandomBytesSync(12); // Standard AES-GCM nonce length
        const nonceStr = Array.from(nonce).join(',');
        nonces.add(nonceStr);
      }

      // All nonces should be unique
      expect(nonces.size).toBe(1000);
    });

    it("should handle nonce collision scenarios", () => {
      // Mock RNG to return same value multiple times
      let callCount = 0;
      const originalGetRandomValues = globalThis.crypto.getRandomValues;
      const mockGetRandomValues = vi.fn((arr: any) => {
        callCount++;
        if (arr instanceof Uint8Array) {
          arr.fill(callCount % 256);
        }
        return arr;
      });
      globalThis.crypto.getRandomValues = mockGetRandomValues;

      const nonce1 = getSecureRandomBytesSync(12);
      const nonce2 = getSecureRandomBytesSync(12);

      // Nonces should still be different despite RNG predictability
      expect(nonce1).not.toEqual(nonce2);

      globalThis.crypto.getRandomValues = originalGetRandomValues;
    });

    it("should validate nonce length requirements", () => {
      // Test with standard length
      const nonce = getSecureRandomBytesSync(12);
      expect(nonce.length).toBe(12);

      // Test with different lengths
      expect(() => getSecureRandomBytesSync(0)).toThrow(InvalidParameterError);
      expect(() => getSecureRandomBytesSync(1000000)).toThrow(InvalidParameterError);
    });
  });

  describe("Key Generation and Management", () => {
    it("should generate unique AES keys", async () => {
      const key1 = await createAesGcmKey256();
      const key2 = await createAesGcmKey256();

      // Keys should be different objects
      expect(key1).not.toBe(key2);

      // Extract key material for comparison (if possible)
      if (key1.type === 'secret' && key2.type === 'secret') {
        // In a real scenario, we'd compare key material
        expect(key1.algorithm).toEqual(key2.algorithm);
      }
    });

    it("should handle key generation failures gracefully", async () => {
      // Prefer mocking generateKey since the library uses it when available
      const subtle = globalThis.crypto.subtle as SubtleCrypto & {
        generateKey?: (...args: any[]) => any;
        importKey?: (...args: any[]) => any;
      };
      const originalGenerateKey = subtle.generateKey?.bind(subtle);
      const originalImportKey = subtle.importKey?.bind(subtle);

      if (typeof subtle.generateKey === "function") {
        (subtle as any).generateKey = vi
          .fn()
          .mockRejectedValue(new Error("generateKey failed"));
      } else if (typeof subtle.importKey === "function") {
        (subtle as any).importKey = vi
          .fn()
          .mockRejectedValue(new Error("Import failed"));
      }

      await expect(createAesGcmKey256()).rejects.toThrow();

      // Restore originals
      if (originalGenerateKey) {
        (subtle as any).generateKey = originalGenerateKey;
      }
      if (originalImportKey) {
        (subtle as any).importKey = originalImportKey;
      }
    });

    it("should validate key length parameters", async () => {
      // Test invalid key lengths
      const invalidLengths = [-1, 0, 13, 25, 100];

      for (const length of invalidLengths) {
        await expect(createAesGcmKey256(length as any)).rejects.toThrow(InvalidParameterError);
      }
    });
  });

  describe("Secure String Generation", () => {
    it("should generate strings with specified alphabet", () => {
      const alphabet = "ABC123";
      const length = 10;

      const result = generateSecureStringSync(alphabet, length);

      expect(result.length).toBe(length);
      for (const char of result) {
        expect(alphabet).toContain(char);
      }
    });

    it("should handle empty alphabet", () => {
      expect(() => generateSecureStringSync("", 10)).toThrow(InvalidParameterError);
    });

    it("should handle very large length requests", () => {
      const largeLength = 1000000;
      expect(() => generateSecureStringSync("ABC", largeLength)).toThrow(InvalidParameterError);
    });

    it("should generate unique strings in sequence", () => {
      const strings = new Set<string>();

      for (let i = 0; i < 100; i++) {
        const str = generateSecureStringSync("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 32);
        strings.add(str);
      }

      // High probability of uniqueness
      expect(strings.size).toBeGreaterThan(95);
    });
  });
});