import { test, expect } from "vitest";
import * as postMessage from "../../src/postMessage";
import {
  __test_resetCryptoStateForUnitTests,
  _setCrypto,
} from "../../src/state";
import { POSTMESSAGE_MAX_PAYLOAD_DEPTH } from "../../src/postMessage";

test("stableStringify depth overflow triggers fingerprint fallback", async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    // reset module-level state
    try {
      postMessage.__test_resetForUnitTests();
    } catch {}
    try {
      if (typeof __test_resetCryptoStateForUnitTests === "function")
        __test_resetCryptoStateForUnitTests();
    } catch {}

    // Build a deep, non-circular object that exceeds POSTMESSAGE_MAX_PAYLOAD_DEPTH
    let deep: any = { leaf: "end" };
    for (let i = 0; i < POSTMESSAGE_MAX_PAYLOAD_DEPTH + 3; i++) {
      deep = { child: deep };
    }

    // Call the test-exposed fingerprint getter. stableStringify should fail and
    // getPayloadFingerprint should take the fallback path and return a string.
    const fp = await (postMessage as any).__test_getPayloadFingerprint(deep);
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
