import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { setCrypto } from "../../src/config";
import { environment } from "../../src/environment";
import * as stateModule from "../../src/state";
const { __test_resetCryptoStateForUnitTests, getCryptoState, CryptoState } =
  stateModule as any;
import { InvalidConfigurationError } from "../../src/errors";

// Minimal fake crypto-like object
const fakeCrypto = {
  getRandomValues(arr: Uint8Array) {
    for (let i = 0; i < arr.length; i++) arr[i] = 1;
    return arr;
  },
};

describe("setCrypto allowInProduction gating", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function") {
      __test_resetCryptoStateForUnitTests();
    }
  });

  afterEach(() => {
    // Clear any global flags
    try {
      // @ts-ignore
      delete (globalThis as any).__SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD;
    } catch {}
    try {
      delete process.env.SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD;
    } catch {}
    if (typeof __test_resetCryptoStateForUnitTests === "function") {
      __test_resetCryptoStateForUnitTests();
    }
  });

  it("throws when called in production without explicit opt-in", () => {
    environment.setExplicitEnv("production");
    expect(() =>
      setCrypto(fakeCrypto as any, { allowInProduction: true }),
    ).toThrow(InvalidConfigurationError);
  });

  it("succeeds when global opt-in flag is set", () => {
    environment.setExplicitEnv("production");
    // @ts-ignore
    (globalThis as any).__SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD = true;
    setCrypto(fakeCrypto as any, { allowInProduction: true });
    expect(getCryptoState()).toBe(CryptoState.Configured);
  });

  it("succeeds when env var opt-in is set", () => {
    environment.setExplicitEnv("production");
    process.env.SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD = "true";
    setCrypto(fakeCrypto as any, { allowInProduction: true });
    expect(getCryptoState()).toBe(CryptoState.Configured);
  });
});
