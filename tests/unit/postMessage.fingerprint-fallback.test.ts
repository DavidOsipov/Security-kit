import { expect, test, afterEach } from "vitest";
import { __test_getPayloadFingerprint, __test_resetForUnitTests } from "../../src/postMessage";
import { __test_resetCryptoStateForUnitTests, _setCrypto } from "../../src/state";

// Ensure global state is cleaned between tests
afterEach(() => {
  try {
    __test_resetForUnitTests();
  } catch {}
  try {
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
  } catch {}
});

// Helper to stub globalThis.crypto with a subtle.digest that throws
function stubCryptoSubtleDigestThrows() {
  const fakeCrypto: Partial<Crypto> = {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;
      return arr;
    },
    subtle: {
      async digest() {
        throw new Error("subtle failure");
      },
    } as unknown as SubtleCrypto,
  };
  // install via state._setCrypto so ensureCrypto picks it up. Do NOT assign
  // to globalThis.crypto directly — it's read-only in some Node runtimes.
  try {
    _setCrypto(fakeCrypto as unknown as Crypto, { allowInProduction: true });
  } catch {
    // ignore production opt-in guard if present in environment
  }
}

test("falls back to salted rolling hash when subtle.digest throws", async () => {
  // Allow test APIs at runtime
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

  // Reset any previous state
  try {
    __test_resetForUnitTests();
  } catch {}
  try {
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
  } catch {}

  stubCryptoSubtleDigestThrows();

  const payload = { a: 1, b: "x" };
  const fp = await __test_getPayloadFingerprint(payload);
  // Fallback path returns a hex string padded to 8 chars
  expect(fp).toMatch(/^[0-9a-f]{8}$/);
});
