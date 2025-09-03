import { describe, it, expect, vi } from "vitest";
import {
  __test_resetForUnitTests,
  __test_getSaltFailureTimestamp,
  __test_setSaltFailureTimestamp,
  __test_ensureFingerprintSalt,
} from "../../src/postMessage";
import * as state from "../../src/state";
import { environment } from "../../src/environment";

// Adversarial tests for ensureFingerprintSalt cooldown/backoff

describe("ensureFingerprintSalt adversarial cooldown", () => {
  it("development fallback: ensureCrypto rejects -> fallback salt produced and cached", async () => {
    environment.setExplicitEnv("development");
    try {
      state.__test_resetCryptoStateForUnitTests?.();
    } catch {}
    __test_resetForUnitTests();

    const rejectErr = new Error("crypto init fail");
    const ensureCrypto = vi
      .spyOn(state, "ensureCrypto")
      .mockImplementation(async () => {
        throw rejectErr;
      });

    // In development we expect a fallback salt to be produced, not an exception
    const salt = await __test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);

    // Ensure no failure timestamp remains (fallback produced a salt)
    const ts = __test_getSaltFailureTimestamp();
    expect(ts).toBeUndefined();

    ensureCrypto.mockRestore();
  });

  it("production cooldown: ensureCrypto rejects -> failure timestamp set and immediate retries fail; after clearing timestamp retry succeeds", async () => {
    environment.setExplicitEnv("production");
    // Allow test-only APIs in this test process so we can call internal reset helpers
    process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";
    try {
      state.__test_resetCryptoStateForUnitTests?.();
    } catch {}
    __test_resetForUnitTests();

    const rejectErr = new Error("crypto init fail");
    const ensureCrypto = vi
      .spyOn(state, "ensureCrypto")
      .mockImplementation(async () => {
        throw rejectErr;
      });

    // First call should reject in production
    await expect(__test_ensureFingerprintSalt()).rejects.toThrow();

    // Failure timestamp should be set
    const ts = __test_getSaltFailureTimestamp();
    expect(typeof ts).toBe("number");

    // Immediate retry should fail fast due to cooldown
    await expect(__test_ensureFingerprintSalt()).rejects.toThrow();

    // Now make ensureCrypto succeed and clear the failure timestamp to simulate cooldown expiry
    ensureCrypto.mockRestore();
    const resolvedCrypto: Crypto = {
      getRandomValues: (array: Uint8Array) => array,
      subtle: undefined,
    } as unknown as Crypto;
    const ensureCryptoSuccess = vi
      .spyOn(state, "ensureCrypto")
      .mockResolvedValue(resolvedCrypto as any);
    __test_setSaltFailureTimestamp?.(undefined);

    // Now retry should succeed
    const saltAfter = await __test_ensureFingerprintSalt();
    expect(saltAfter).toBeInstanceOf(Uint8Array);

    ensureCryptoSuccess.mockRestore();
    delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  });
});
