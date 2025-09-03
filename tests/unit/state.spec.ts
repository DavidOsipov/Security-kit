// SPDX-License-Identifier: MIT
import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  _setCrypto,
  ensureCrypto,
  ensureCryptoSync,
  _sealSecurityKit,
  CryptoState,
  getCryptoState,
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
    // Reset test state if available (use runtime require to avoid build-time __TEST__ guards)
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const state = require("../../src/state");
      if (typeof state.__test_resetCryptoStateForUnitTests === "function")
        state.__test_resetCryptoStateForUnitTests();
    } catch {}
  });

  afterEach(() => {
    // ensure we clear anything we set
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const state = require("../../src/state");
      if (typeof state.__test_resetCryptoStateForUnitTests === "function")
        state.__test_resetCryptoStateForUnitTests();
    } catch {}
    try {
      // try to restore global crypto if tests changed it
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (
        (globalThis as any).crypto &&
        (globalThis as any).__test_replaced_crypto
      ) {
        (globalThis as any).crypto = (globalThis as any).__test_replaced_crypto;
        delete (globalThis as any).__test_replaced_crypto;
      }
    } catch {}
  });

  it("_setCrypto accepts a valid crypto and configures state", async () => {
    const fake = makeFakeCrypto();
    _setCrypto(fake, { allowInProduction: false });
    expect(getCryptoState()).toBe(CryptoState.Configured);
    // ensureCrypto resolves to the injected provider
    const c = await ensureCrypto();
    expect(c).toBeDefined();
    expect(c).toBe(fake);
  });

  it("ensureCryptoSync throws when no global crypto and none configured", () => {
    // ensure reset state
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const state = require("../../src/state");
      if (typeof state.__test_resetCryptoStateForUnitTests === "function")
        state.__test_resetCryptoStateForUnitTests();
    } catch {}
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
    // ensure fresh unconfigured state
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const state = require("../../src/state");
      if (typeof state.__test_resetCryptoStateForUnitTests === "function")
        state.__test_resetCryptoStateForUnitTests();
    } catch {}

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
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const state = require("../../src/state");
      if (typeof state.__test_resetCryptoStateForUnitTests === "function")
        state.__test_resetCryptoStateForUnitTests();
    } catch {}

    const current = getCryptoState();
    if (current === CryptoState.Sealed) {
      // Already sealed: ensure further configuration is blocked
      expect(() => _setCrypto(null)).toThrow(InvalidConfigurationError);
      return;
    }

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
    expect(() => _setCrypto(null)).toThrow(InvalidConfigurationError);
  });
});
