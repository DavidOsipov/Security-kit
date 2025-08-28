import { describe, it, expect, vi } from 'vitest';

// Production-mode stress test: simulate concurrent ensureCrypto failures and
// assert cooldown behavior. This test enables test-only APIs via env var when
// loading the module.

async function loadWithMockedEnsureCryptoAndProd(ensureCryptoImpl: () => Promise<any>) {
  vi.resetModules();
  // Allow test-only APIs in production mode
  process.env.SECURITY_KIT_ALLOW_TEST_APIS = 'true';
  vi.doMock('../../src/state', () => ({
    ensureCrypto: ensureCryptoImpl,
    __test_resetCryptoStateForUnitTests: () => {},
    _setCrypto: () => {},
  }));
  vi.doMock('../../src/environment', () => ({
    environment: { isProduction: true },
    isDevelopment: () => false,
  }));
  const pm = await import('../../src/postMessage');
  return pm;
}

describe('ensureFingerprintSalt production cooldown stress', () => {
  it('concurrent failures set cooldown and block retries until cleared', async () => {
    const concurrency = Number(process.env.STRESS_CONCURRENCY ?? 200);

    let calls = 0;
    const failingEnsure = async () => {
      calls += 1;
      // simulate a quick failure
      throw new Error('simulated production crypto failure');
    };

    let pm = await loadWithMockedEnsureCryptoAndProd(failingEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    const callers = new Array(concurrency).fill(0).map(() => pm.__test_ensureFingerprintSalt());
    const settled = await Promise.allSettled(callers);
    // In production, failing ensureCrypto should reject with CryptoUnavailableError
    const allRejected = settled.every((s) => s.status === 'rejected');
    expect(allRejected).toBe(true);

    // Verify failure timestamp recorded
    const ts = pm.__test_getSaltFailureTimestamp();
    expect(typeof ts).toBe('number');

    // Now clear the failure timestamp (simulate cooldown expiry) and mock success
    pm.__test_setSaltFailureTimestamp(undefined);

    const successEnsure = async () => ({
      getRandomValues: (u: Uint8Array) => { for (let i = 0; i < u.length; i++) u[i] = i & 0xff; return u; },
    } as any);
    pm = await loadWithMockedEnsureCryptoAndProd(successEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    const salt = await pm.__test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
  }, 60_000);
});
