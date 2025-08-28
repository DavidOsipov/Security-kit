import { test, expect, vi } from 'vitest';
import { __test_getPayloadFingerprint, __test_resetForUnitTests, __test_ensureFingerprintSalt } from '../../src/postMessage';
import * as state from '../../src/state';
import { environment } from '../../src/environment';
import { CryptoUnavailableError } from '../../src/errors';

test('computeFingerprintFromString uses subtle.digest when available', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    __test_resetForUnitTests();

    const fakeDigest = vi.fn(async (_algo: unknown, _buffer: ArrayBuffer) => {
      const out = new Uint8Array(32);
      for (let i = 0; i < out.length; i++) out[i] = (i * 2) & 0xff;
      return out.buffer;
    });

    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => { for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff; return buf; },
      subtle: { digest: fakeDigest },
    } as unknown as Crypto;

    if (typeof (state as any)._setCrypto === 'function') {
      (state as any)._setCrypto(fakeCrypto);
    } else {
      (globalThis as any).crypto = fakeCrypto;
    }

    // ensure salt is created via test helper which will use our fakeCrypto.getRandomValues
    const salt = await __test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);

  const fp = await __test_getPayloadFingerprint('hello world');
    expect(typeof fp).toBe('string');
    expect(fp.length).toBeGreaterThan(0);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test('ensureFingerprintSalt throws in production when crypto missing', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  const prev = (environment as any).__explicitEnv;
  try {
    environment.setExplicitEnv('production');
    __test_resetForUnitTests();

    // Make sure crypto is not available synchronously
    try {
      delete (globalThis as any).crypto;
    } catch {}

    await expect(__test_ensureFingerprintSalt()).rejects.toThrow(CryptoUnavailableError);
  } finally {
    try {
      environment.setExplicitEnv(prev === undefined ? 'development' : prev);
    } catch {}
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
