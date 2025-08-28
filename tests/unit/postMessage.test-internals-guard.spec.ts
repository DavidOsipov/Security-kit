import { expect, test } from 'vitest';
import * as postMessage from '../../src/postMessage';
import { environment } from '../../src/environment';

test('__test accessors throw when test APIs not allowed and env not set', async () => {
  // Ensure global guard is not set and environment is production-like
  try {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  } catch {}

  // Temporarily set explicit environment to production to force guard
  const env = await import('../../src/environment');
  env.environment.setExplicitEnv('production');

  let threw = false;
  try {
    // This should throw because test APIs are disallowed in production
    postMessage.__test_resetForUnitTests();
  } catch (err) {
    threw = true;
    expect((err as Error).message).toContain('Test-only APIs are disabled');
  }
  expect(threw).toBe(true);

  // restore environment for tests
  env.environment.setExplicitEnv('development');
});

test('__test accessors succeed when global allow flag is set', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    // These should not throw now
    await postMessage.__test_ensureFingerprintSalt();
    const maybe = postMessage.__test_getSaltFailureTimestamp();
    expect(typeof maybe === 'undefined' || typeof maybe === 'number').toBe(true);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test('__test accessors succeed when process.env allows test APIs', async () => {
  const prev = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  try {
    process.env.SECURITY_KIT_ALLOW_TEST_APIS = 'true';
    environment.setExplicitEnv('production');
    // should not throw
    await postMessage.__test_ensureFingerprintSalt();
    const maybe = postMessage.__test_getSaltFailureTimestamp();
    expect(typeof maybe === 'undefined' || typeof maybe === 'number').toBe(true);
  } finally {
    environment.setExplicitEnv('development');
    if (typeof prev === 'undefined') delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    else process.env.SECURITY_KIT_ALLOW_TEST_APIS = prev;
  }
});
