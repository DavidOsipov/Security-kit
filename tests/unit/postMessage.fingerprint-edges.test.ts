import { expect, test, afterEach, vi } from "vitest";
import {
  __test_getPayloadFingerprint,
  __test_ensureFingerprintSalt,
  __test_resetForUnitTests,
} from "../../src/postMessage";
import * as state from "../../src/state";
import { CryptoUnavailableError } from "../../src/errors";

// Allow test APIs at runtime
(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try {
    __test_resetForUnitTests();
  } catch {}
  try {
    if (
      typeof (state as any).__test_resetCryptoStateForUnitTests === "function"
    )
      (state as any).__test_resetCryptoStateForUnitTests();
  } catch {}
});

// Helper: a crypto-like object without subtle
const cryptoNoSubtle: Partial<Crypto> = {
  getRandomValues: (arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) arr[i] = (i * 3) & 0xff;
    return arr;
  },
};

// Helper: a crypto with subtle.digest that rejects
const cryptoSubtleReject: Partial<Crypto> = {
  getRandomValues: (arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) arr[i] = (i + 7) & 0xff;
    return arr;
  },
  subtle: {
    digest: async () => {
      throw new Error("subtle rejected");
    },
  } as unknown as SubtleCrypto,
};

// Test: ensureCrypto resolves to crypto with no subtle -> fallback hash used
test("falls back when subtle is undefined on crypto object", async () => {
  vi.spyOn(state, "ensureCrypto").mockResolvedValue(cryptoNoSubtle as Crypto);
  const fp = await __test_getPayloadFingerprint({ x: 1 });
  // fallback should be hex string (8 chars)
  expect(fp).toMatch(/^[0-9a-f]{8}$/);
});

// Test: subtle exists but digest rejects -> fallback hash used
test("falls back when subtle.digest rejects", async () => {
  vi.spyOn(state, "ensureCrypto").mockResolvedValue(
    cryptoSubtleReject as Crypto,
  );
  const fp = await __test_getPayloadFingerprint({ x: 2 });
  expect(fp).toMatch(/^[0-9a-f]{8}$/);
});

// Test: ensureCrypto rejects entirely -> fallback deterministic salt/time-based path
test("uses time-entropy salt when ensureCrypto rejects", async () => {
  vi.spyOn(state, "ensureCrypto").mockRejectedValue(
    new CryptoUnavailableError(),
  );
  // ensure salt can be produced even when ensureCrypto fails
  const salt = await __test_ensureFingerprintSalt();
  expect(salt).toBeInstanceOf(Uint8Array);
  const fp = await __test_getPayloadFingerprint({ y: 3 });
  // Because ensureCrypto rejected, fingerprint may still be hex fallback or FINGERPRINT_ERR
  expect(typeof fp).toBe("string");
});
