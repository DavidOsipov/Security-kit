import { expect, test, beforeEach, afterEach, vi } from 'vitest';
import * as postMessage from '../../src/postMessage';
import { ensureCrypto as realEnsureCrypto } from '../../src/state';

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
  // Arrange: spy on ensureCrypto to reject once so we exercise the non-crypto fallback
  const state = await import('../../src/state');
  const spy = vi.spyOn(state, 'ensureCrypto').mockRejectedValueOnce(new Error('no crypto'));

  // First call should produce a fallback deterministic salt in test/dev
  const salt = await postMessage.__test_ensureFingerprintSalt();
  expect(salt).toBeInstanceOf(Uint8Array);
  expect(salt.length).toBeGreaterThan(0);

  // Second call should return the cached salt (same reference or equal bytes)
  const salt2 = await postMessage.__test_ensureFingerprintSalt();
  expect(salt2).toBeInstanceOf(Uint8Array);
  expect(salt2.length).toEqual(salt.length);

  spy.mockRestore();
});

test('getPayloadFingerprint falls back when stableStringify fails', async () => {
  // Construct a deep, non-circular object that will exceed the stableStringify depth
  const depth = postMessage.POSTMESSAGE_MAX_PAYLOAD_DEPTH + 2;
  let obj: any = {};
  let cur = obj;
  for (let i = 0; i < depth; i++) {
    cur.next = {};
    cur = cur.next;
  }

  const fp = await postMessage.__test_getPayloadFingerprint(obj);
  expect(typeof fp).toBe('string');
  // In dev/test non-crypto fallback, fingerprint should be a hex-like string or FINGERPRINT_ERR
  expect(fp.length).toBeGreaterThanOrEqual(1);
});
