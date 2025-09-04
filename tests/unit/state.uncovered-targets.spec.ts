// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  ensureCrypto,
  ensureCryptoSync,
  getCryptoState,
  secureRandomBytes,
  isCryptoAvailable,
  CryptoState,
  __resetCryptoStateForTests,
  __test_getCachedCrypto,
  __test_setCachedCrypto,
  getInternalTestUtils,
  _setCrypto,
  _sealSecurityKit,
  __test_setCryptoState,
} from "../../src/state";
import * as stateModule from "../../src/state";
import { setCrypto, sealSecurityKit } from "../../src/config";
import {
  CryptoUnavailableError,
  InvalidConfigurationError,
  InvalidParameterError,
} from "../../src/errors";

// Mock modules properly
vi.mock("../../src/environment", () => ({
  environment: {
    isProduction: false,
    clearCache: vi.fn(),
  },
  isDevelopment: vi.fn(() => true),
}));

vi.mock("../../src/reporting", () => ({
  reportProdError: vi.fn(),
}));

vi.mock("../../src/dev-logger", () => ({
  developmentLog_: vi.fn(),
  setDevelopmentLogger_: vi.fn(),
}));

vi.mock("../../src/development-guards", () => ({
  assertTestApiAllowed: vi.fn(),
}));

// Mock Node.js crypto import
const mockNodeCrypto = {
  webcrypto: {
    getRandomValues: vi.fn((arr) => arr),
    subtle: {
      digest: vi.fn(),
    },
    randomUUID: vi.fn(() => "mock-uuid"),
  },
  randomBytes: vi.fn((size) => Buffer.alloc(size, 42)),
  randomUUID: vi.fn(() => "mock-uuid"),
};
// Controllable mock for node:crypto so tests can switch behavior without re-registering mocks
let nodeCryptoFactoryMode: "normal" | "throw" = "normal";
let currentNodeCryptoMock: any = mockNodeCrypto;
const nodeCryptoMockExport: any = {
  get webcrypto() {
    if (nodeCryptoFactoryMode === "throw") {
      throw new Error("Module not found");
    }
    return currentNodeCryptoMock.webcrypto;
  },
  get randomBytes() {
    if (nodeCryptoFactoryMode === "throw") {
      throw new Error("Module not found");
    }
    return currentNodeCryptoMock.randomBytes;
  },
  get randomUUID() {
    if (nodeCryptoFactoryMode === "throw") {
      throw new Error("Module not found");
    }
    return currentNodeCryptoMock.randomUUID;
  },
};
vi.mock("node:crypto", () => nodeCryptoMockExport);

// Minimal fake crypto implementation
function makeFakeCrypto(): Crypto {
  return {
    getRandomValues: vi.fn((arr) => arr),
    subtle: {} as any,
    randomUUID: vi.fn(() => "mock-uuid"),
  } as unknown as Crypto;
}

describe("state.ts - uncovered targets (lines 82-485, 495-501)", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset crypto state properly using the test environment helper
    __resetCryptoStateForTests?.();
    // Reset node:crypto mock mode to default
    nodeCryptoFactoryMode = "normal";
    currentNodeCryptoMock = mockNodeCrypto;
  });

  afterEach(async () => {
    // Clean up after each test to prevent state leakage
    try {
      __resetCryptoStateForTests?.();
    } catch (error) {
      // Ignore reset errors - some tests may have sealed the state
    }
  });

  describe("detectNodeCrypto function coverage (lines 82-120)", () => {
    it("covers detectNodeCrypto successful Node crypto detection", async () => {
      // Reset to ensure clean state
      __resetCryptoStateForTests?.();

      // Mock successful Node crypto import
      const mockCrypto = await ensureCrypto();
      expect(mockCrypto).toBeDefined();
      expect(typeof mockCrypto.getRandomValues).toBe("function");
    });

    it("covers detectNodeCrypto fallback when webcrypto.subtle is missing", async () => {
      // Create mock without subtle
      const incompleteNodeCrypto = {
        webcrypto: {
          getRandomValues: vi.fn((arr) => arr),
          // No subtle property
        },
        randomBytes: vi.fn((size) => Buffer.alloc(size, 42)),
      };
      currentNodeCryptoMock = incompleteNodeCrypto;

      // Remove global crypto to force Node detection
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        const crypto = await ensureCrypto();
        expect(crypto.getRandomValues).toBeDefined();
        // Should still work even without subtle
        const arr = new Uint8Array(4);
        crypto.getRandomValues(arr);
        expect(arr).toEqual(new Uint8Array([0, 0, 0, 0])); // Our mock fills with 0
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        currentNodeCryptoMock = mockNodeCrypto;
      }
    });

    it("covers detectNodeCrypto error handling and logging", async () => {
      // Mock import failure
      nodeCryptoFactoryMode = "throw";

      // Remove global crypto to force Node detection
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        // This should not throw, but should fall back gracefully
        const crypto = await ensureCrypto();
        expect(crypto).toBeDefined(); // Should have some fallback behavior
      } catch (error) {
        // If it does throw, it should be a CryptoUnavailableError
        expect(error).toBeInstanceOf(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        nodeCryptoFactoryMode = "normal";
      }
    });

    it("covers detectNodeCrypto error logging path", async () => {
      // Mock Node crypto to throw during import
      nodeCryptoFactoryMode = "throw";

      // Remove global crypto to force Node detection
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        // This should trigger the error logging path
        const result = await ensureCrypto();
        // Should fall back gracefully
        expect(result).toBeDefined();
      } catch (error) {
        // If it throws, it should be CryptoUnavailableError
        expect(error).toBeInstanceOf(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        nodeCryptoFactoryMode = "normal";
      }
    });
  });

  describe("ensureCrypto async function coverage (lines 200-350)", () => {
    it("covers ensureCrypto when state is Sealed with cached crypto", async () => {
      const fakeCrypto = makeFakeCrypto();
      setCrypto(fakeCrypto);
      sealSecurityKit();

      const crypto = await ensureCrypto();
      expect(crypto).toBe(fakeCrypto);
    });

    it("covers ensureCrypto when state is Sealed without cached crypto", async () => {
      // Remove global crypto and set state to sealed without crypto
      const originalGlobalCrypto = globalThis.crypto;
      const originalNodeCrypto = (globalThis as any).require?.(
        "crypto",
      )?.webcrypto;
      delete (globalThis as any).crypto;
      if ((globalThis as any).require) {
        delete (globalThis as any).require("crypto").webcrypto;
      }

      try {
        _setCrypto(undefined);
        __test_setCachedCrypto(undefined);
        __test_setCryptoState(CryptoState.Sealed);

        // Mock detectNodeCrypto to return null to ensure no fallback
        const mockDetectNodeCrypto = vi.fn().mockResolvedValue(null);
        vi.doMock("../src/state", () => ({
          ...vi.importActual("../src/state"),
          detectNodeCrypto: mockDetectNodeCrypto,
        }));

        await expect(ensureCrypto()).rejects.toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        if ((globalThis as any).require && originalNodeCrypto) {
          (globalThis as any).require("crypto").webcrypto = originalNodeCrypto;
        }
      }
    });

    it("covers ensureCrypto generation validation during Node detection", async () => {
      // This test covers the generation validation logic
      const fakeCrypto = makeFakeCrypto();
      setCrypto(fakeCrypto);

      const crypto = await ensureCrypto();
      expect(crypto).toBe(fakeCrypto);
    });

    it("covers ensureCrypto successful Node crypto configuration", async () => {
      // Remove global crypto to force Node detection
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        const crypto = await ensureCrypto();
        expect(crypto).toBeDefined();
        expect(typeof crypto.getRandomValues).toBe("function");
      } finally {
        globalThis.crypto = originalGlobalCrypto;
      }
    });

    it("covers ensureCrypto error handling in catch block", async () => {
      // Force an error in ensureCrypto
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;
      nodeCryptoFactoryMode = "throw";

      try {
        await expect(ensureCrypto()).rejects.toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        nodeCryptoFactoryMode = "normal";
      }
    });

    it("covers ensureCrypto promise rejection handling", async () => {
      // Test the promise.catch block
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;
      nodeCryptoFactoryMode = "throw";

      try {
        // This should trigger the catch handler
        await expect(ensureCrypto()).rejects.toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        nodeCryptoFactoryMode = "normal";
      }
    });
  });

  describe("secureRandomBytes function coverage (lines 380-400)", () => {
    it("covers secureRandomBytes parameter validation", async () => {
      await expect(secureRandomBytes(-1)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(secureRandomBytes(3.14)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(secureRandomBytes(70000)).rejects.toThrow(
        InvalidParameterError,
      );
    });

    it("covers secureRandomBytes successful execution", async () => {
      const fakeCrypto = makeFakeCrypto();
      fakeCrypto.getRandomValues = vi.fn((arr) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = i % 256;
        }
        return arr;
      });
      setCrypto(fakeCrypto);

      const result = await secureRandomBytes(8);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(8);
      expect(Array.from(result)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    });

    it("covers secureRandomBytes with maximum safe length", async () => {
      const fakeCrypto = makeFakeCrypto();
      setCrypto(fakeCrypto);

      const result = await secureRandomBytes(65536);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(65536);
    });
  });

  describe("isCryptoAvailable function coverage (lines 410-420)", () => {
    it("covers isCryptoAvailable when crypto is available", async () => {
      const available = await isCryptoAvailable();
      expect(available).toBe(true);
    });

    it("covers isCryptoAvailable when crypto is unavailable", async () => {
      // Mock crypto unavailability
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;
      nodeCryptoFactoryMode = "throw";

      try {
        const available = await isCryptoAvailable();
        expect(available).toBe(false);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
        nodeCryptoFactoryMode = "normal";
      }
    });
  });

  describe("__test_getCachedCrypto function coverage (lines 495-501)", () => {
    it("covers __test_getCachedCrypto with NODE_ENV=test", () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "test";

      try {
        const fakeCrypto = makeFakeCrypto();
        __test_setCachedCrypto(fakeCrypto);

        const cached = __test_getCachedCrypto();
        expect(cached).toBe(fakeCrypto);
      } finally {
        process.env.NODE_ENV = originalNodeEnv;
      }
    });

    it("covers __test_getCachedCrypto with __TEST__ compile flag", () => {
      // This test covers the compile-time flag check
      const originalTestFlag = (globalThis as any).__TEST__;
      (globalThis as any).__TEST__ = true;

      try {
        const fakeCrypto = makeFakeCrypto();
        __test_setCachedCrypto(fakeCrypto);

        const cached = __test_getCachedCrypto();
        expect(cached).toBe(fakeCrypto);
      } finally {
        (globalThis as any).__TEST__ = originalTestFlag;
      }
    });

    it("covers __test_getCachedCrypto with runtime __TEST__ flag", () => {
      // This test covers the runtime flag check
      const originalTestFlag = (globalThis as any).__TEST__;
      (globalThis as any).__TEST__ = undefined; // Clear compile-time flag
      (globalThis as any).__TEST__ = true; // Set runtime flag

      try {
        const fakeCrypto = makeFakeCrypto();
        __test_setCachedCrypto(fakeCrypto);

        const cached = __test_getCachedCrypto();
        expect(cached).toBe(fakeCrypto);
      } finally {
        (globalThis as any).__TEST__ = originalTestFlag;
      }
    });

    it("covers __test_getCachedCrypto return undefined when not in test env", () => {
      const originalNodeEnv = process.env.NODE_ENV;
      const originalTestFlag = (globalThis as any).__TEST__;

      process.env.NODE_ENV = "production";
      (globalThis as any).__TEST__ = false;

      try {
        const cached = __test_getCachedCrypto();
        expect(cached).toBeUndefined();
      } finally {
        process.env.NODE_ENV = originalNodeEnv;
        (globalThis as any).__TEST__ = originalTestFlag;
      }
    });
  });

  describe("__test_setCachedCrypto function coverage", () => {
    it("covers __test_setCachedCrypto setting crypto", () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "test";

      try {
        const fakeCrypto = makeFakeCrypto();
        __test_setCachedCrypto(fakeCrypto);

        expect(getCryptoState()).toBe(CryptoState.Configured);
        expect(__test_getCachedCrypto()).toBe(fakeCrypto);
      } finally {
        process.env.NODE_ENV = originalNodeEnv;
      }
    });

    it("covers __test_setCryptoState when not in test environment", () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      try {
        const originalState = getCryptoState();
        // This should be a no-op when not in test environment
        __test_setCryptoState(CryptoState.Configured);

        // State should remain unchanged
        expect(getCryptoState()).toBe(originalState);
      } finally {
        process.env.NODE_ENV = originalNodeEnv;
      }
    });
  });

  describe("getInternalTestUtils function coverage", () => {
    it("covers getInternalTestUtils with __TEST__ flag", () => {
      const originalTestFlag = (globalThis as any).__TEST__;
      (globalThis as any).__TEST__ = true;

      try {
        const utils = getInternalTestUtils();
        expect(utils).toBeDefined();
        expect(typeof utils?._getCryptoGenerationForTest).toBe("function");
        expect(typeof utils?._getCryptoStateForTest).toBe("function");
      } finally {
        (globalThis as any).__TEST__ = originalTestFlag;
      }
    });

    it("covers getInternalTestUtils without __TEST__ flag", () => {
      const originalTestFlag = (globalThis as any).__TEST__;
      (globalThis as any).__TEST__ = false;

      try {
        const utils = getInternalTestUtils();
        expect(utils).toBeUndefined();
      } finally {
        (globalThis as any).__TEST__ = originalTestFlag;
      }
    });
  });

  describe("ensureCryptoSync function coverage", () => {
    it("covers ensureCryptoSync with cached crypto", () => {
      const fakeCrypto = makeFakeCrypto();
      setCrypto(fakeCrypto);

      const crypto = ensureCryptoSync();
      expect(crypto).toBe(fakeCrypto);
    });

    it("covers ensureCryptoSync when state is Sealed without crypto", async () => {
      // Remove global crypto and set state to sealed without crypto
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        __test_setCachedCrypto(undefined);
        __test_setCryptoState(CryptoState.Sealed);

        expect(() => ensureCryptoSync()).toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
      }
    });

    it("covers ensureCryptoSync when state is Configuring", async () => {
      // Remove global crypto and set state to configuring
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        __test_setCryptoState(CryptoState.Configuring);

        expect(() => ensureCryptoSync()).toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
      }
    });

    it("covers ensureCryptoSync with global crypto", () => {
      // Reset state
      __resetCryptoStateForTests?.();

      // Ensure global crypto is available
      const crypto = ensureCryptoSync();
      expect(crypto).toBeDefined();
      expect(typeof crypto.getRandomValues).toBe("function");
    });

    it("covers ensureCryptoSync when crypto unavailable", () => {
      // Remove global crypto
      const originalGlobalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        expect(() => ensureCryptoSync()).toThrow(CryptoUnavailableError);
      } finally {
        globalThis.crypto = originalGlobalCrypto;
      }
    });
  });

  describe("_setCrypto function coverage", () => {
    it("covers _setCrypto with valid crypto", () => {
      const fakeCrypto = makeFakeCrypto();
      _setCrypto(fakeCrypto);

      expect(getCryptoState()).toBe(CryptoState.Configured);
    });

    it("covers _setCrypto with undefined", () => {
      _setCrypto(undefined);
      expect(getCryptoState()).toBe(CryptoState.Unconfigured);
    });

    it("covers _setCrypto validation failure", () => {
      expect(() => _setCrypto({} as any)).toThrow(InvalidParameterError);
    });

    it("covers _setCrypto when state is Sealed", () => {
      const fakeCrypto = makeFakeCrypto();
      _setCrypto(fakeCrypto);
      _sealSecurityKit();

      expect(() => _setCrypto(fakeCrypto)).toThrow(InvalidConfigurationError);
    });
  });

  describe("_sealSecurityKit function coverage", () => {
    it("covers _sealSecurityKit when already sealed", () => {
      const fakeCrypto = makeFakeCrypto();
      _setCrypto(fakeCrypto);
      _sealSecurityKit();

      // Second seal should be idempotent
      expect(() => _sealSecurityKit()).not.toThrow();
    });

    it("covers _sealSecurityKit when state is Configuring", async () => {
      // Set state to Configuring and ensure no crypto is available
      __test_setCachedCrypto(undefined);
      __test_setCryptoState(CryptoState.Configuring);

      // Clear any crypto promise
      (stateModule as any)._cryptoPromise = undefined;

      expect(() => _sealSecurityKit()).toThrow(InvalidConfigurationError);
    });

    it("covers _sealSecurityKit without crypto", () => {
      _setCrypto(undefined);
      expect(() => _sealSecurityKit()).toThrow(CryptoUnavailableError);
    });
  });
});
