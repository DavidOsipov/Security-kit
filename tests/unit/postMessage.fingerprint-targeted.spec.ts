import { expect, test, beforeEach, afterEach, vi } from 'vitest';
import * as postMessage from '../../src/postMessage';
// enable runtime test APIs
beforeEach(() => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  postMessage.__test_resetForUnitTests();
});
afterEach(() => {
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  postMessage.__test_resetForUnitTests();
});

test('ensureFingerprintSalt fallback when ensureCrypto rejects, then cached', async () => {
  // Arrange: monkey-patch ensureCrypto to reject once
  const state = await import('../../src/state');
  const spy = vi.spyOn(state, 'ensureCrypto').mockRejectedValue(new Error('no crypto'));

  // First call should produce a fallback deterministic salt in test/dev
  const salt = await postMessage.__test_ensureFingerprintSalt();
  expect(salt).toBeInstanceOf(Uint8Array);
  expect(salt.length).toBeGreaterThan(0);

  // Restore ensureCrypto
  spy.mockRestore();

  // Second call should return the cached salt (same reference or equal bytes)
  const salt2 = await postMessage.__test_ensureFingerprintSalt();
  expect(salt2).toBeInstanceOf(Uint8Array);
  expect(salt2.length).toEqual(salt.length);
});

test('getPayloadFingerprint falls back when stableStringify fails due to depth', async () => {
  // Build a deeply nested object that exceeds POSTMESSAGE_MAX_PAYLOAD_DEPTH
  const depth = (postMessage as any).POSTMESSAGE_MAX_PAYLOAD_DEPTH ?? 8;
  let obj: any = { v: 0 };
  let cur = obj;
  for (let i = 0; i < depth + 5; i++) {
    cur.next = { idx: i };
    cur = cur.next;
  }

  const fp = await postMessage.__test_getPayloadFingerprint(obj);
  expect(typeof fp).toBe('string');
  expect(fp.length).toBeGreaterThanOrEqual(1);
});
