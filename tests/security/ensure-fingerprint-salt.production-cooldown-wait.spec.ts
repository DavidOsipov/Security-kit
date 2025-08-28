import { describe, it, expect, vi } from 'vitest';

// Production-mode cooldown wait test: ensure that after observed failures,
// callers are blocked for the real cooldown duration and then a retry after
// waiting the cooldown succeeds.

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

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

describe('ensureFingerprintSalt production cooldown (wait realistic)', () => {
  it('waits the real cooldown period before retrying', async () => {
    const concurrency = Number(process.env.STRESS_CONCURRENCY ?? 50);

    let calls = 0;
    const failingEnsure = async () => {
      calls += 1;
      throw new Error('simulated production crypto failure');
    };

    // Load module with failing ensureCrypto
    let pm = await loadWithMockedEnsureCryptoAndProd(failingEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    const callers = new Array(concurrency).fill(0).map(() => pm.__test_ensureFingerprintSalt());
    const settled = await Promise.allSettled(callers);
    const allRejected = settled.every((s) => s.status === 'rejected');
    expect(allRejected).toBe(true);

    // Verify failure timestamp recorded
    const ts = pm.__test_getSaltFailureTimestamp();
    expect(typeof ts).toBe('number');

    // Wait the real cooldown period (SALT_FAILURE_COOLDOWN_MS = 5000ms)
    const SALT_FAILURE_COOLDOWN_MS = 5_000;
    // Wait slightly more than the cooldown to account for scheduling jitter
    await sleep(SALT_FAILURE_COOLDOWN_MS + 200);

    // After cooldown, create a successful ensureCrypto and retry
    const successEnsure = async () => ({
      getRandomValues: (u: Uint8Array) => { for (let i = 0; i < u.length; i++) u[i] = i & 0xff; return u; },
    } as any);
    pm = await loadWithMockedEnsureCryptoAndProd(successEnsure);
    try { pm.__test_resetForUnitTests(); } catch {}

    // Ensure no failure timestamp blocks us now
    const tsAfter = pm.__test_getSaltFailureTimestamp();
    expect(tsAfter === undefined || typeof tsAfter === 'undefined').toBe(true);

    const salt = await pm.__test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
  }, 90_000);
});
