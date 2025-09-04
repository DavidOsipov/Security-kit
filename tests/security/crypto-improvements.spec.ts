// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
/**
 * Security tests for crypto.ts improvements and new security features.
 * Tests the enhanced security controls, constants, and capability detection.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fc from "fast-check";
import {
  getSecureRandomInt,
  generateSecureStringAsync,
  generateSecureIdBytesSync,
  hasRandomUUIDSync,
  getCryptoCapabilities,
  MAX_ID_BYTES_LENGTH,
  MAX_RANDOM_BYTES_SYNC,
  generateSRI,
} from "../../src/crypto.js";
import { InvalidParameterError } from "../../src/errors.js";
import * as environment from "../../src/environment.js";

describe("crypto.ts security improvements", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("random integer distribution (sanity)", () => {
    it("produces values within specified ranges", async () => {
      // Test with a small range where we can reasonably expect some distribution
      const min = 0;
      const max = 10;
      const draws = 1000;
      const results = new Set<number>();

      for (let i = 0; i < draws; i++) {
        const v = await getSecureRandomInt(min, max);
        expect(v).toBeGreaterThanOrEqual(min);
        expect(v).toBeLessThanOrEqual(max);
        results.add(v);
      }

      // With 1000 draws in range 0-10, we should see at least 5 different values
      // This is a reasonable statistical expectation without being too strict
      expect(results.size).toBeGreaterThan(4);
    });
  });

  describe("secure string generation constraints", () => {
    it("respects size and alphabet membership", async () => {
      const alphabet = "abcdef";
      const size = 64;
      const s = await generateSecureStringAsync(alphabet, size);
      expect(s).toHaveLength(size);
      for (const char of s) {
        expect(alphabet).toContain(char);
      }
    });

    it("handles small alphabets correctly", async () => {
      // Small alphabets are allowed but may be less efficient
      const result = await generateSecureStringAsync("a", 10);
      expect(result).toBe("aaaaaaaaaa");
    });

    it("rejects invalid alphabet sizes", async () => {
      await expect(generateSecureStringAsync("", 10)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(
        generateSecureStringAsync("a".repeat(300), 10),
      ).rejects.toThrow(InvalidParameterError);
    });

    it("rejects duplicate characters in alphabet", async () => {
      await expect(generateSecureStringAsync("aa", 10)).rejects.toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("wipeable bytes", () => {
    it("returns wipeable buffers within documented limits", () => {
      const bytes = generateSecureIdBytesSync(
        Math.min(16, MAX_ID_BYTES_LENGTH),
      );
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBeLessThanOrEqual(MAX_ID_BYTES_LENGTH);
    });

    it("enforces maximum length limits", () => {
      expect(() => generateSecureIdBytesSync(MAX_ID_BYTES_LENGTH + 1)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("capability detection functions", () => {
    it("hasRandomUUIDSync returns boolean", () => {
      const result = hasRandomUUIDSync();
      expect(typeof result).toBe("boolean");
    });

    it("getCryptoCapabilities returns expected shape", () => {
      const caps = getCryptoCapabilities();
      expect(caps).toHaveProperty("hasRandomUUIDSync");
      expect(caps).toHaveProperty("hasRandomUUIDAsyncLikely");
      expect(caps).toHaveProperty("hasSyncCrypto");
      expect(caps).toHaveProperty("hasSubtle");
      expect(caps).toHaveProperty("hasDigest");
      expect(caps).toHaveProperty("hasBigUint64");
      expect(typeof caps.hasRandomUUIDSync).toBe("boolean");
      expect(typeof caps.hasRandomUUIDAsyncLikely).toBe("boolean");
      expect(typeof caps.hasSyncCrypto).toBe("boolean");
      expect(typeof caps.hasSubtle).toBe("boolean");
      expect(typeof caps.hasDigest).toBe("boolean");
      expect(typeof caps.hasBigUint64).toBe("boolean");
    });

    it("getCryptoCapabilities returns frozen object", () => {
      const caps = getCryptoCapabilities();
      expect(Object.isFrozen(caps)).toBe(true);
    });
  });

  describe("security constants validation", () => {
    it("MAX_RANDOM_BYTES_SYNC is properly defined", () => {
      expect(typeof MAX_RANDOM_BYTES_SYNC).toBe("number");
      expect(MAX_RANDOM_BYTES_SYNC).toBeGreaterThan(0);
      expect(MAX_RANDOM_BYTES_SYNC).toBeLessThanOrEqual(65536);
    });

    it("MAX_ID_BYTES_LENGTH is properly defined", () => {
      expect(typeof MAX_ID_BYTES_LENGTH).toBe("number");
      expect(MAX_ID_BYTES_LENGTH).toBeGreaterThan(0);
      expect(MAX_ID_BYTES_LENGTH).toBeLessThanOrEqual(65536);
    });

    it("constants are reasonable for security", () => {
      // Ensure sync limits are reasonable for performance
      expect(MAX_RANDOM_BYTES_SYNC).toBeGreaterThanOrEqual(1024);
      expect(MAX_RANDOM_BYTES_SYNC).toBeLessThanOrEqual(8192);
    });
  });

  describe("generateSRI development warnings", () => {
    let consoleWarnSpy: any;

    beforeEach(() => {
      consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it("warns about string inputs in development", async () => {
      // Mock development environment
      vi.spyOn(environment, "isDevelopment").mockReturnValue(true);

      await generateSRI("test", "sha256");

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining("generateSRI received a string input"),
      );
    });

    it("does not warn in production", async () => {
      // Mock production environment
      vi.spyOn(environment, "isDevelopment").mockReturnValue(false);

      await generateSRI("test", "sha256");

      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it("warns about large inputs in development", async () => {
      vi.spyOn(environment, "isDevelopment").mockReturnValue(true);

      const largeInput = "x".repeat(10000);
      await generateSRI(largeInput, "sha256");

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Wiping a large buffer"),
      );
    });
  });

  describe("input validation and error handling", () => {
    it("rejects invalid byte lengths", () => {
      expect(() => generateSecureIdBytesSync(-1)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureIdBytesSync(0)).toThrow(InvalidParameterError);
      expect(() => generateSecureIdBytesSync(MAX_ID_BYTES_LENGTH + 1)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureIdBytesSync(NaN)).toThrow(
        InvalidParameterError,
      );
      expect(() => generateSecureIdBytesSync(Infinity)).toThrow(
        InvalidParameterError,
      );
    });

    it("rejects invalid string generation parameters", async () => {
      await expect(generateSecureStringAsync("", 10)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(
        generateSecureStringAsync("a".repeat(300), 10),
      ).rejects.toThrow(InvalidParameterError);
      await expect(generateSecureStringAsync("abc", -1)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(generateSecureStringAsync("abc", 0)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(generateSecureStringAsync("aa", 10)).rejects.toThrow(
        InvalidParameterError,
      );
    });

    it("rejects invalid random int ranges", async () => {
      await expect(getSecureRandomInt(10, 5)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(getSecureRandomInt(NaN, 10)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(getSecureRandomInt(5, NaN)).rejects.toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("performance and security boundaries", () => {
    it("respects sync operation limits for DoS prevention", () => {
      const start = performance.now();
      generateSecureIdBytesSync(128); // Use valid size within limits
      const end = performance.now();

      // Should complete within reasonable time (adjust based on environment)
      expect(end - start).toBeLessThan(100); // 100ms should be plenty
    });

    it("generates different values on subsequent calls", () => {
      const a = generateSecureIdBytesSync(16);
      const b = generateSecureIdBytesSync(16);

      // Very unlikely to be identical (probability ~ 2^-128)
      expect(a).not.toEqual(b);
    });
  });
});
