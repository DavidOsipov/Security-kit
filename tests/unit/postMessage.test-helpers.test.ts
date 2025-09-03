import { test, expect } from "vitest";
import {
  __test_ensureFingerprintSalt,
  __test_getSaltFailureTimestamp,
  __test_setSaltFailureTimestamp,
  __test_resetForUnitTests,
} from "../../src/postMessage";

test("test helpers: ensureFingerprintSalt and salt timestamp manipulation", async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    // reset first
    __test_resetForUnitTests();

    // Initially no timestamp
    expect(__test_getSaltFailureTimestamp()).toBeUndefined();

    // Ensure salt can be retrieved (dev/test fallback path)
    const salt = await __test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    // Manually set a failure timestamp and read it back
    __test_setSaltFailureTimestamp(123456);
    expect(__test_getSaltFailureTimestamp()).toBe(123456);

    // Reset again and ensure timestamp is cleared
    __test_resetForUnitTests();
    expect(__test_getSaltFailureTimestamp()).toBeUndefined();
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
