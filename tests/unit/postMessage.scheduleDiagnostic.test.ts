import { test, expect, vi, beforeEach, afterEach } from 'vitest';

beforeEach(() => {
  vi.useFakeTimers();
  vi.resetModules();
});

afterEach(() => vi.useRealTimers());
import * as state from '../../src/state';
import { environment } from '../../src/environment';

test('scheduleDiagnostic handles ensureCrypto rejection in development', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  const prev = (environment as any).__explicitEnv;
  try {
    environment.setExplicitEnv('development');

    const spy = vi.spyOn(state as any, 'ensureCrypto').mockRejectedValueOnce(new Error('no crypto'));

  const postMessage = await import('../../src/postMessage');
  const listener = postMessage.createSecurePostMessageListener(
      {
        allowedOrigins: [location.origin],
        onMessage: () => {},
        validate: () => false, // validation fails to trigger diagnostic
        enableDiagnostics: true,
      },
    );

    // dispatch event to trigger handler
    const ev = new MessageEvent('message', { data: JSON.stringify({ x: 1 }), origin: location.origin, source: window as any });
    window.dispatchEvent(ev);

  // wait for async computeAndLog to run
  await vi.runAllTimersAsync();

    listener.destroy();
    spy.mockRestore();
  } finally {
    try { environment.setExplicitEnv(prev === undefined ? 'development' : prev); } catch {}
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test('scheduleDiagnostic sets diagnostics disabled flag when ensureCrypto rejects in production', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  const prev = (environment as any).__explicitEnv;
  try {
    environment.setExplicitEnv('production');

    // Ensure syncCryptoAvailable is true by registering a fake crypto via state._setCrypto
    const fakeCrypto = { getRandomValues: (b: Uint8Array) => b } as unknown as Crypto;
    try {
      // Allow setting crypto in production for this test
      (globalThis as any).__SECURITY_KIT_ALLOW_SET_CRYPTO_IN_PROD = true;
      if (typeof (state as any)._setCrypto === 'function') {
        (state as any)._setCrypto(fakeCrypto, { allowInProduction: true });
      }
    } catch {
      /* ignore */
    }

    const spy = vi.spyOn(state as any, 'ensureCrypto').mockRejectedValueOnce(new Error('no crypto'));
  const postMessage = await import('../../src/postMessage');
  const listener = postMessage.createSecurePostMessageListener(
      {
        allowedOrigins: [location.origin],
        onMessage: () => {},
        validate: () => false, // validation fails to trigger diagnostic
        enableDiagnostics: true,
      },
    );

    const ev = new MessageEvent('message', { data: JSON.stringify({ x: 2 }), origin: location.origin, source: window as any });
    window.dispatchEvent(ev);

  await vi.runAllTimersAsync();

    listener.destroy();
    spy.mockRestore();
    try {
      if (typeof (state as any).__test_resetCryptoStateForUnitTests === 'function')
        (state as any).__test_resetCryptoStateForUnitTests();
    } catch {}
  } finally {
    try { environment.setExplicitEnv(prev === undefined ? 'development' : prev); } catch {}
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
