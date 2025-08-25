import { describe, it, expect, beforeEach } from "vitest";
import * as state from "../../src/state";
import { setCrypto, sealSecurityKit } from "../../src/config";
import { CryptoUnavailableError, InvalidConfigurationError } from "../../src/errors";

const { __test_resetCryptoStateForUnitTests, CryptoState } = (state as any);

describe("state lifecycle and configuration", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
  });

  it("ensureCrypto throws when no crypto is available", async () => {
    const globalCryptoAvailable = !!(
      (globalThis as any).crypto &&
      typeof (globalThis as any).crypto.getRandomValues === "function"
    );
    if (globalCryptoAvailable) {
      await expect(state.ensureCrypto()).resolves.toHaveProperty("getRandomValues");
    } else {
      await expect(state.ensureCrypto()).rejects.toThrow(CryptoUnavailableError);
    }
  });

  it("setCrypto configures and ensureCrypto returns the injected provider", async () => {
    const fakeCrypto: any = { getRandomValues: (arr: Uint8Array) => arr };
    setCrypto(fakeCrypto as any);
    const c = await state.ensureCrypto();
    expect(c).toBe(fakeCrypto);
    expect(state.getCryptoState()).toBe(CryptoState.Configured);
  });

  it("ensureCryptoSync uses global crypto when available via setCrypto", () => {
    const fakeCrypto: any = { getRandomValues: (arr: Uint8Array) => arr };
    setCrypto(fakeCrypto as any);
    const c = state.ensureCryptoSync();
    expect(c).toBe(fakeCrypto);
  });

  it("sealSecurityKit behavior depends on environment crypto availability", async () => {
    // reset ensures no provider
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
    const currentState = state.getCryptoState();
    const globalCryptoAvailable = !!(
      (globalThis as any).crypto &&
      typeof (globalThis as any).crypto.getRandomValues === "function"
    );
    if (currentState === CryptoState.Sealed) {
      // already sealed: idempotent no-throw
      expect(() => sealSecurityKit()).not.toThrow();
      return;
    }
    if (globalCryptoAvailable) {
      // If global crypto is present, sealing should succeed after ensureCrypto
      await state.ensureCrypto();
      expect(() => sealSecurityKit()).not.toThrow();
      return;
    }
    // No global crypto, and not sealed: sealing should fail because no provider
    expect(() => sealSecurityKit()).toThrow(CryptoUnavailableError);
  });

  it("sealSecurityKit prevents further configuration once set", async () => {
    const fakeCrypto: any = { getRandomValues: (arr: Uint8Array) => arr };
    const currentState = state.getCryptoState();
    if (currentState === CryptoState.Sealed) {
      // Already sealed: setCrypto should throw immediately
      expect(() => setCrypto(null)).toThrow(InvalidConfigurationError);
      return;
    }

    // Otherwise, configure and seal, then verify further configuration is blocked
    setCrypto(fakeCrypto as any);
    // ensureCrypto to initialize internal state
    await state.ensureCrypto();
    sealSecurityKit();
    try {
      setCrypto(null);
      // If no error thrown, that's a test failure
      throw new Error("setCrypto did not throw after sealing");
    } catch (err: any) {
      expect(err).toBeInstanceOf(InvalidConfigurationError);
    }
  });
});
