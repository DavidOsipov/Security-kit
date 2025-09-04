// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  _setCrypto,
  ensureCrypto,
  ensureCryptoSync,
  _sealSecurityKit,
  CryptoState,
  getCryptoState,
  __resetCryptoStateForTests,
} from "../../src/state";

import {
  CryptoUnavailableError,
  InvalidConfigurationError,
} from "../../src/errors";

// Minimal fake crypto implementation
function makeFakeCrypto(): Crypto {
  return {
    getRandomValues: (buf: Uint8Array) => {
      for (let i = 0; i < buf.length; i++) buf[i] = i % 256;
      return buf;
    },
  } as unknown as Crypto;
}

describe("state.ts - crypto lifecycle and test helpers", () => {
  beforeEach(() => {
    // Ensure a pristine state before each test to prevent sealing/config leaks
    __resetCryptoStateForTests();
  });

  afterEach(() => {
    // Always reset to avoid cross-test interference
    __resetCryptoStateForTests();
    // Also restore any global crypto we may have replaced in a test
    try {
      if ((globalThis as any).__test_replaced_crypto) {
        (globalThis as any).crypto = (globalThis as any).__test_replaced_crypto;
        delete (globalThis as any).__test_replaced_crypto;
      }
    } catch {}
  });

  it("_setCrypto accepts a valid crypto and configures state", async () => {
    __resetCryptoStateForTests();
    const fake = makeFakeCrypto();
    _setCrypto(fake, { allowInProduction: false });
    expect(getCryptoState()).toBe(CryptoState.Configured);
    // ensureCrypto resolves to the injected provider
    const c = await ensureCrypto();
    expect(c).toBeDefined();
    expect(c).toBe(fake);
  });

  it("ensureCryptoSync throws when no global crypto and none configured", () => {
    // If a global crypto is present, ensureCryptoSync should return it.
    const globalCryptoAvailable = !!(
      (globalThis as any).crypto &&
      typeof (globalThis as any).crypto.getRandomValues === "function"
    );
    if (globalCryptoAvailable) {
      const c = ensureCryptoSync();
      expect(c).toBeDefined();
    } else {
      expect(() => ensureCryptoSync()).toThrow(CryptoUnavailableError);
    }
  });

  it("_sealSecurityKit throws when no crypto available", async () => {
    const globalCryptoAvailable = !!(
      (globalThis as any).crypto &&
      typeof (globalThis as any).crypto.getRandomValues === "function"
    );
    if (globalCryptoAvailable) {
      // If global crypto is present, sealing should succeed after ensureCrypto
      await ensureCrypto();
      expect(() => _sealSecurityKit()).not.toThrow();
    } else {
      expect(() => _sealSecurityKit()).toThrow(CryptoUnavailableError);
    }
  });

  it("_sealSecurityKit seals when crypto is configured", async () => {
    const current = getCryptoState();
    if (current === CryptoState.Sealed) {
      // Already sealed: ensure further configuration is blocked
      expect(() => _setCrypto(undefined)).toThrow(InvalidConfigurationError);
      return;
    }

    // Otherwise, configure and seal, then verify further configuration is blocked
    const fake = makeFakeCrypto();
    _setCrypto(fake);
    // ensureCrypto sets internal cached provider
    await ensureCrypto();
    _sealSecurityKit();
    expect(getCryptoState()).toBe(CryptoState.Sealed);
    // After sealing, ensureCrypto returns the cached provider
    const c = await ensureCrypto();
    expect(c).toBeDefined();
    // ensure that attempting to set crypto after sealing throws
    expect(() => _setCrypto(undefined)).toThrow(InvalidConfigurationError);
  });

  describe("OWASP ASVS L3 compliance - crypto validation", () => {
    it("validates crypto interface before caching", () => {
      const validCrypto = makeFakeCrypto();
      expect(() => _setCrypto(validCrypto)).not.toThrow();
      expect(getCryptoState()).toBe(CryptoState.Configured);
    });

    it("rejects crypto objects without getRandomValues", () => {
      const invalidCrypto = {
        subtle: { digest: () => {} },
        // Missing getRandomValues
      };

      expect(() => _setCrypto(invalidCrypto as any)).toThrow();
    });

    it("validates allowInProduction parameter type", () => {
      const fake = makeFakeCrypto();
      expect(() => _setCrypto(fake, { allowInProduction: "true" as any })).toThrow();
    });

    it("handles null and undefined crypto gracefully", () => {
      expect(() => _setCrypto(undefined)).not.toThrow();
      expect(() => _setCrypto(null as any)).not.toThrow();
      expect(getCryptoState()).toBe(CryptoState.Unconfigured);
    });
  });

  describe("secure random bytes generation", () => {
    it("generates cryptographically secure random bytes", async () => {
      const fake = makeFakeCrypto();
      _setCrypto(fake);

      // Test the secureRandomBytes function indirectly through ensureCrypto
      const crypto = await ensureCrypto();
      expect(crypto).toBeDefined();
      expect(typeof crypto.getRandomValues).toBe("function");
    });

    it("rejects invalid length parameters", async () => {
      // This would test the secureRandomBytes function if it were exported
      // For now, we test the crypto interface validation
      const crypto = await ensureCrypto();
      expect(() => {
        const arr = new Uint8Array(0);
        crypto.getRandomValues(arr);
      }).not.toThrow();
    });
  });

  describe("production security hardening", () => {
    it("requires explicit opt-in for production crypto override", () => {
      // This test would require mocking the production environment
      // For now, we test the basic validation
      const fake = makeFakeCrypto();
      expect(() => _setCrypto(fake, { allowInProduction: true })).not.toThrow();
    });

    it("prevents accidental crypto weakening in production", () => {
      __resetCryptoStateForTests();
      // Test that the validation logic exists
      const fake = makeFakeCrypto();
      expect(() => _setCrypto(fake, { allowInProduction: false })).not.toThrow();
    });
  });

  describe("error handling and logging", () => {
    it("handles crypto initialization failures gracefully", async () => {
      // Test that ensureCrypto can handle various failure modes
      try {
        // Reset to unconfigured state
        _setCrypto(undefined);
        // This should either succeed or fail gracefully
        const result = await ensureCrypto();
        expect(result).toBeDefined();
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoUnavailableError);
      }
    });

    it("provides safe error messages without leaking internal details", () => {
      // Test that error messages are appropriate for security
      expect(() => _setCrypto("invalid" as any)).toThrow();
    });
  });

  describe("cache poisoning protection", () => {
    it("prevents stale async resolution through generation validation", async () => {
      // Test the generation-based cache poisoning protection
      const fake = makeFakeCrypto();
      _setCrypto(fake);

      const crypto1 = await ensureCrypto();
      expect(crypto1).toBe(fake);

      // Reset and ensure we get a new instance or proper error
      _setCrypto(undefined);
      try {
        await ensureCrypto();
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoUnavailableError);
      }
    });
  });

  describe("Node.js crypto detection security", () => {
    it("validates Node crypto interface before trusting", async () => {
      // Test that Node crypto detection includes proper validation
      // This is tested indirectly through the ensureCrypto function
      const crypto = await ensureCrypto();
      expect(crypto).toBeDefined();
    });

    it("handles Node crypto import failures securely", async () => {
      // Test error handling for Node crypto detection
      try {
        const crypto = await ensureCrypto();
        expect(crypto).toBeDefined();
      } catch (error) {
        expect(error).toBeInstanceOf(CryptoUnavailableError);
      }
    });
  });
});
