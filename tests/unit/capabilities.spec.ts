import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  hasRandomUUIDSync,
  getCryptoCapabilities,
} from "../../src/capabilities.js";

describe("capabilities", () => {
  describe("hasRandomUUIDSync", () => {
    it("returns true when crypto.randomUUID is available and is a function", () => {
      // Mock crypto with randomUUID
      const mockCrypto = {
        randomUUID: vi.fn(),
      };

      // Mock globalThis.crypto
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      expect(hasRandomUUIDSync()).toBe(true);

      // Restore original crypto
      Object.defineProperty(globalThis, "crypto", {
        value: originalCrypto,
        writable: true,
        configurable: true,
      });
    });

    it("returns false when crypto.randomUUID is not available", () => {
      // Mock crypto without randomUUID
      const mockCrypto = {};

      // Mock globalThis.crypto
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      expect(hasRandomUUIDSync()).toBe(false);

      // Restore original crypto
      Object.defineProperty(globalThis, "crypto", {
        value: originalCrypto,
        writable: true,
        configurable: true,
      });
    });

    it("returns false when crypto is undefined", () => {
      // Mock globalThis without crypto
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, "crypto", {
        value: undefined,
        writable: true,
        configurable: true,
      });

      expect(hasRandomUUIDSync()).toBe(false);

      // Restore original crypto
      Object.defineProperty(globalThis, "crypto", {
        value: originalCrypto,
        writable: true,
        configurable: true,
      });
    });

    it("returns false when crypto.randomUUID is not a function", () => {
      // Mock crypto with randomUUID as non-function
      const mockCrypto = {
        randomUUID: "not-a-function",
      };

      // Mock globalThis.crypto
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      expect(hasRandomUUIDSync()).toBe(false);

      // Restore original crypto
      Object.defineProperty(globalThis, "crypto", {
        value: originalCrypto,
        writable: true,
        configurable: true,
      });
    });
  });

  describe("getCryptoCapabilities", () => {
    let originalCrypto: Crypto | undefined;
    let originalBigUint64Array: typeof BigUint64Array | undefined;

    beforeEach(() => {
      originalCrypto = globalThis.crypto;
      originalBigUint64Array = globalThis.BigUint64Array;
    });

    afterEach(() => {
      Object.defineProperty(globalThis, "crypto", {
        value: originalCrypto,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis, "BigUint64Array", {
        value: originalBigUint64Array,
        writable: true,
        configurable: true,
      });
    });

    it("returns full capabilities when all crypto features are available", () => {
      const mockCrypto = {
        getRandomValues: vi.fn(),
        subtle: {
          digest: vi.fn(),
        },
        randomUUID: vi.fn(),
      };

      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      const capabilities = getCryptoCapabilities();

      expect(capabilities).toEqual({
        hasSyncCrypto: true,
        hasSubtle: true,
        hasDigest: true,
        hasRandomUUIDSync: true,
        hasRandomUUIDAsyncLikely: true,
        hasBigUint64: true,
      });
    });

    it("returns minimal capabilities when crypto is not available", () => {
      Object.defineProperty(globalThis, "crypto", {
        value: undefined,
        writable: true,
        configurable: true,
      });

      Object.defineProperty(globalThis, "BigUint64Array", {
        value: undefined,
        writable: true,
        configurable: true,
      });

      const capabilities = getCryptoCapabilities();

      expect(capabilities).toEqual({
        hasSyncCrypto: false,
        hasSubtle: false,
        hasDigest: false,
        hasRandomUUIDSync: false,
        hasRandomUUIDAsyncLikely: false,
        hasBigUint64: false,
      });
    });

    it("returns partial capabilities when some crypto features are missing", () => {
      const mockCrypto = {
        getRandomValues: vi.fn(),
        // No subtle
        // No randomUUID
      };

      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      Object.defineProperty(globalThis, "BigUint64Array", {
        value: undefined,
        writable: true,
        configurable: true,
      });

      const capabilities = getCryptoCapabilities();

      expect(capabilities).toEqual({
        hasSyncCrypto: true,
        hasSubtle: false,
        hasDigest: false,
        hasRandomUUIDSync: false,
        hasRandomUUIDAsyncLikely: true,
        hasBigUint64: false,
      });
    });

    it("returns capabilities with subtle but no digest function", () => {
      const mockCrypto = {
        getRandomValues: vi.fn(),
        subtle: {
          // No digest function
        },
        randomUUID: vi.fn(),
      };

      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      const capabilities = getCryptoCapabilities();

      expect(capabilities).toEqual({
        hasSyncCrypto: true,
        hasSubtle: true,
        hasDigest: false,
        hasRandomUUIDSync: true,
        hasRandomUUIDAsyncLikely: true,
        hasBigUint64: true,
      });
    });

    it("returns capabilities with randomUUID as non-function", () => {
      const mockCrypto = {
        getRandomValues: vi.fn(),
        subtle: {
          digest: vi.fn(),
        },
        randomUUID: "not-a-function",
      };

      Object.defineProperty(globalThis, "crypto", {
        value: mockCrypto,
        writable: true,
        configurable: true,
      });

      const capabilities = getCryptoCapabilities();

      expect(capabilities).toEqual({
        hasSyncCrypto: true,
        hasSubtle: true,
        hasDigest: true,
        hasRandomUUIDSync: false,
        hasRandomUUIDAsyncLikely: true,
        hasBigUint64: true,
      });
    });
  });
});
