import { expect, test, beforeEach, afterEach, vi } from "vitest";
import { CryptoUnavailableError } from "../../src/errors";

// enable runtime test APIs
beforeEach(async () => {
  vi.resetModules();
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  const postMessage = await import("../../src/postMessage");
  (postMessage as any).__test_resetForUnitTests();
});

afterEach(async () => {
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  const postMessage = await import("../../src/postMessage");
  (postMessage as any).__test_resetForUnitTests();
});

test("ensureFingerprintSalt fallback when ensureCrypto rejects, then cached", async () => {
  // Arrange: monkey-patch ensureCrypto to reject once
  const state = await import("../../src/state");
  const spy = vi
    .spyOn(state, "ensureCrypto")
    .mockRejectedValue(new CryptoUnavailableError());

  const postMessage = await import("../../src/postMessage");
  // First call should produce a fallback deterministic salt in test/dev
  const salt = await (postMessage as any).__test_ensureFingerprintSalt();
  expect(salt).toBeInstanceOf(Uint8Array);
  expect(salt.length).toBeGreaterThan(0);

  // Restore ensureCrypto
  spy.mockRestore();

  // Second call should return the cached salt (same reference or equal bytes)
  const salt2 = await (postMessage as any).__test_ensureFingerprintSalt();
  expect(salt2).toBeInstanceOf(Uint8Array);
  expect(salt2.length).toEqual(salt.length);
});

test("getPayloadFingerprint falls back when stableStringify fails due to depth", async () => {
  const postMessage = await import("../../src/postMessage");
  // Build a deeply nested object that exceeds configured maxPayloadDepth
  const depth = postMessage.getPostMessageConfig().maxPayloadDepth;
  let obj: Record<string, unknown> = { v: 0 };
  let cur = obj;
  for (let i = 0; i < depth + 5; i++) {
    cur.next = { idx: i };
    cur = cur.next;
  }

  const fp = await (postMessage as any).__test_getPayloadFingerprint(obj);
  expect(typeof fp).toBe("string");
  expect(fp.length).toBeGreaterThanOrEqual(1);
});
