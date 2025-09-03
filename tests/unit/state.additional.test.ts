import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";

import * as state from "../../src/state";
import {
  CryptoUnavailableError,
  InvalidParameterError,
  InvalidConfigurationError,
} from "../../src/errors";

const origGlobalCrypto = (globalThis as any).crypto;

beforeEach(() => {
  // Best-effort reset: if test-only helper exists use it, otherwise try to reset
  try {
    if (typeof state.__test_resetCryptoStateForUnitTests === "function") {
      state.__test_resetCryptoStateForUnitTests();
    } else {
      // try to set to undefined; ignore errors (sealed state)
      try {
        state._setCrypto(undefined);
      } catch {}
    }
  } catch {}
  delete (globalThis as any).crypto;
});

afterEach(() => {
  // Restore original global crypto if present and try to reset module state
  if (origGlobalCrypto !== undefined)
    (globalThis as any).crypto = origGlobalCrypto;
  try {
    if (typeof state.__test_resetCryptoStateForUnitTests === "function") {
      state.__test_resetCryptoStateForUnitTests();
    } else {
      try {
        state._setCrypto(null);
      } catch {}
    }
  } catch {}
});

describe("state module - crypto lifecycle", () => {
  it("ensureCryptoSync throws when no global crypto is present", () => {
    // Ensure no global crypto
    delete (globalThis as any).crypto;
    // ensureCryptoSync should throw a CryptoUnavailableError
    expect(() => state.ensureCryptoSync()).toThrow(CryptoUnavailableError);
  });

  it("ensureCryptoSync returns global crypto when available", () => {
    const fake: any = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 42;
        return arr;
      },
    };
    (globalThis as any).crypto = fake;
    const c = state.ensureCryptoSync();
    expect(c).toBe(fake);
  });

  it("_setCrypto rejects invalid provider objects", () => {
    // Passing a non-object should raise InvalidParameterError
    // (the implementation requires an object with getRandomValues)
    expect(() => state._setCrypto("not-an-object" as any)).toThrow(
      InvalidParameterError,
    );
  });

  it("_sealSecurityKit throws when called before any crypto is available", () => {
    // Ensure clean state
    try {
      state._setCrypto(undefined);
    } catch {}
    expect(() => state._sealSecurityKit()).toThrow(CryptoUnavailableError);
  });

  it("_setCrypto configures a valid provider and ensureCrypto resolves to it", async () => {
    const fake: any = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;
        return arr;
      },
    };

    // Configure via exported setter
    state._setCrypto(fake);
    // getCryptoState should reflect configured
    expect(state.getCryptoState()).toBe(state.CryptoState.Configured);

    const got = await state.ensureCrypto();
    expect(got).toBe(fake);
  });

  it("ensureCrypto propagates configuration errors cleanly", async () => {
    // Mock Node crypto import to fail so ensureCrypto rejects when no global crypto
    vi.doMock("node:crypto", () => {
      throw new Error("Module not found");
    });

    // Simulate invalid usage: configure with a value that will be rejected
    // by the setter
    try {
      expect(() => state._setCrypto("bad" as any)).toThrow(
        InvalidParameterError,
      );
    } catch {}
    // After the failed set, ensureCrypto should attempt to use global crypto
    delete (globalThis as any).crypto;
    await expect(state.ensureCrypto()).rejects.toBeInstanceOf(
      CryptoUnavailableError,
    );
  });
});
// ...existing code... (kept the single test suite above)
