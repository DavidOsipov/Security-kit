import { describe, it, expect, beforeEach, vi } from 'vitest';

// Helper: load the postMessage module after installing a mock for state
async function loadWithMockedEnsureCrypto(
  ensureCryptoImpl: () => Promise<any>,
) {
  vi.resetModules();
  vi.doMock('../../src/state', () => ({
    ensureCrypto: ensureCryptoImpl,
    // minimal test helpers referenced by postMessage during tests
    __test_resetCryptoStateForUnitTests: () => {},
    _setCrypto: () => {},
  }));
  const pm = await import('../../src/postMessage');
  return pm;
}

async function loadWithMockedEnsureCryptoAndEnv(
  ensureCryptoImpl: () => Promise<any>,
  isProduction: boolean,
) {
  vi.resetModules();
  vi.doMock('../../src/state', () => ({
    ensureCrypto: ensureCryptoImpl,
    __test_resetCryptoStateForUnitTests: () => {},
    _setCrypto: () => {},
  }));
  vi.doMock('../../src/environment', () => ({
    environment: { isProduction },
    isDevelopment: () => !isProduction,
  }));
  if (isProduction) process.env.SECURITY_KIT_ALLOW_TEST_APIS = 'true';
  const pm = await import('../../src/postMessage');
  return pm;
}

describe('ensureFingerprintSalt concurrency and cooldown', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('deduplicates concurrent successful ensureCrypto calls', async () => {
    let calls = 0;
    const mockEnsure = async () => {
      calls += 1;
      return {
        getRandomValues: (u: Uint8Array) => {
          for (let i = 0; i < u.length; i++) u[i] = i & 0xff;
          return u;
        },
      } as any;
    };

    const pm = await loadWithMockedEnsureCrypto(mockEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    const promises: Promise<Uint8Array>[] = [];
    for (let i = 0; i < 20; i++) promises.push(pm.__test_ensureFingerprintSalt());

    const results = await Promise.all(promises);
    expect(results.every((r) => r.length === results[0].length)).toBe(true);
    expect(calls).toBeGreaterThanOrEqual(1);
  });

  it('sets failure timestamp and rejects concurrently when ensureCrypto fails (production)', async () => {
    let calls = 0;
    const mockEnsure = async () => {
      calls += 1;
      throw new Error('simulated crypto failure');
    };

    const pm = await loadWithMockedEnsureCryptoAndEnv(mockEnsure, true);
    try { pm.__test_resetForUnitTests(); } catch {}

    const callers = new Array(10).fill(0).map(() => pm.__test_ensureFingerprintSalt());
    const settled = await Promise.allSettled(callers);
    expect(settled.every((s) => s.status === 'rejected')).toBe(true);

    const ts = pm.__test_getSaltFailureTimestamp();
    expect(typeof ts).toBe('number');
    expect(calls).toBeGreaterThanOrEqual(1);
  });

  it('allows retry after cooldown expiry', async () => {
  const failEnsure = async () => { throw new Error('fail'); };
  let pm = await loadWithMockedEnsureCryptoAndEnv(failEnsure, true);
    try { pm.__test_resetForUnitTests(); } catch {}
    await Promise.allSettled([pm.__test_ensureFingerprintSalt(), pm.__test_ensureFingerprintSalt()]);
    const ts = pm.__test_getSaltFailureTimestamp();
    expect(typeof ts).toBe('number');

    pm.__test_setSaltFailureTimestamp(undefined);

    const successEnsure = async () => ({
      getRandomValues: (u: Uint8Array) => { for (let i = 0; i < u.length; i++) u[i] = (i + 1) & 0xff; return u; },
    } as any);
    pm = await loadWithMockedEnsureCrypto(successEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    const salt = await pm.__test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
  });
});
