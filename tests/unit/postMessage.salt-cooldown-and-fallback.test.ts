import { expect, test, beforeEach } from "vitest";

// Tests for salt cooldown and fallback fingerprint behavior

test("ensureFingerprintSalt throws when on cooldown in production", async () => {
  const env = await import("../../src/environment");
  const pm = await import("../../src/postMessage");
  const state = await import("../../src/state");

  // Allow test-only APIs in this controlled test so we can exercise internals
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  env.environment.setExplicitEnv("production");

  try {
    // Explicitly set the salt failure timestamp to now to simulate recent failure
    pm.__test_setSaltFailureTimestamp(Date.now());

    await expect(pm.__test_ensureFingerprintSalt()).rejects.toThrow(
      /Salt generation failed recently/,
    );
  } finally {
    // cleanup
    pm.__test_setSaltFailureTimestamp(undefined);
    env.environment.setExplicitEnv("development");
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test("computeFingerprintFromString returns FINGERPRINT_ERR when no salt and no subtle", async () => {
  const pm = await import("../../src/postMessage");
  const state = await import("../../src/state");

  // Ensure a clean test state and development environment
  const env = await import("../../src/environment");
  env.environment.setExplicitEnv("development");
  pm.__test_resetForUnitTests();
  try {
    if (state.__test_resetCryptoStateForUnitTests)
      state.__test_resetCryptoStateForUnitTests();

    // Force ensureFingerprintSalt to throw via recent failure timestamp (cooldown)
    pm.__test_setSaltFailureTimestamp(Date.now());

    const s = await pm.__test_getPayloadFingerprint({ a: 1 });
    // When salt generation is on cooldown and no subtle available, we expect a fallback token string
    expect(typeof s).toBe("string");
  } finally {
    pm.__test_setSaltFailureTimestamp(undefined);
    env.environment.setExplicitEnv("development");
  }
});
