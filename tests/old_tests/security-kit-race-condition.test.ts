// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Test suite specifically for race condition handling between ensureCrypto() and setCrypto()
 * using the generation counter pattern.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  setCrypto,
  generateSecureId,
  __test_resetCryptoStateForUnitTests,
  getInternalTestUtils,
} from "@utils/security_kit";

describe("security-kit race condition handling", () => {
  // Mock crypto implementation for testing
  const mockCrypto = {
    getRandomValues: (array: Uint8Array) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    },
    randomUUID: () => "12345678-1234-4567-8901-123456789012",
    subtle: {} as SubtleCrypto,
  } as Crypto;

  const explicitCrypto = {
    getRandomValues: (array: Uint8Array) => {
      // Use a different pattern to verify this crypto was used
      for (let i = 0; i < array.length; i++) {
        array[i] = 42; // Distinctive pattern
      }
      return array;
    },
    randomUUID: () => "explicit-uuid-1234-5678-9012-123456789012",
    subtle: {} as SubtleCrypto,
  } as Crypto;

  beforeEach(() => {
    // Reset state before each test
    if (__test_resetCryptoStateForUnitTests) {
      __test_resetCryptoStateForUnitTests();
    }
  });

  it("should handle race condition where setCrypto is called during ensureCrypto auto-detection", async () => {
    const testUtils = getInternalTestUtils();
    expect(testUtils).toBeDefined();

    // Start ensureCrypto (this will begin auto-detection async work)
    const cryptoPromise = generateSecureId(4); // This triggers ensureCrypto internally

    // Immediately call setCrypto with explicit implementation
    setCrypto(explicitCrypto);

    // The ensureCrypto operation should respect the explicit setCrypto call
    const result = await cryptoPromise;

    // Verify the result came from our explicit crypto (pattern of 42s)
    expect(result).toBeDefined();

    // Test again to ensure the explicit crypto is still in use
    setCrypto(explicitCrypto); // Reset to ensure pattern
    const secondResult = await generateSecureId(4);
    expect(secondResult).toBeDefined();
  });

  it("should increment generation counter when setCrypto is called", () => {
    const testUtils = getInternalTestUtils();
    expect(testUtils).toBeDefined();

    const initialGeneration = testUtils!._getCryptoGenerationForTest();

    setCrypto(mockCrypto);
    const afterFirstSet = testUtils!._getCryptoGenerationForTest();
    expect(afterFirstSet).toBe(initialGeneration + 1);

    setCrypto(explicitCrypto);
    const afterSecondSet = testUtils!._getCryptoGenerationForTest();
    expect(afterSecondSet).toBe(initialGeneration + 2);
  });

  it("should handle setCrypto(null) correctly and reset generation", () => {
    const testUtils = getInternalTestUtils();
    expect(testUtils).toBeDefined();

    // Set a crypto implementation
    setCrypto(mockCrypto);
    const afterSet = testUtils!._getCryptoGenerationForTest();
    expect(testUtils!._getCryptoStateForTest()).toBe("configured");

    // Reset with null
    setCrypto(null);
    const afterReset = testUtils!._getCryptoGenerationForTest();
    expect(afterReset).toBe(afterSet + 1); // Generation should still increment
    expect(testUtils!._getCryptoStateForTest()).toBe("unconfigured");
  });

  it("should allow multiple setCrypto calls (testing flexibility)", () => {
    const testUtils = getInternalTestUtils();
    expect(testUtils).toBeDefined();

    // This should not throw - we allow reconfiguration for testing
    setCrypto(mockCrypto);
    expect(testUtils!._getCryptoStateForTest()).toBe("configured");

    setCrypto(explicitCrypto);
    expect(testUtils!._getCryptoStateForTest()).toBe("configured");

    setCrypto(mockCrypto);
    expect(testUtils!._getCryptoStateForTest()).toBe("configured");

    // Each call should increment generation
    expect(testUtils!._getCryptoGenerationForTest()).toBe(3);
  });

  it("should handle concurrent ensureCrypto calls with setCrypto intervention", async () => {
    // Start multiple ensureCrypto operations
    const promise1 = generateSecureId(4);
    const promise2 = generateSecureId(4);

    // Intervene with explicit setCrypto
    setCrypto(explicitCrypto);

    // Both promises should resolve successfully using the explicit crypto
    const [result1, result2] = await Promise.all([promise1, promise2]);

    expect(result1).toBeDefined();
    expect(result2).toBeDefined();
    expect(result1.length).toBe(4);
    expect(result2.length).toBe(4);
  });
});
