import { expect, test, vi } from 'vitest';

test('__test accessors throw when test APIs not allowed and env not set', async () => {
  vi.resetModules();
  // Ensure global guard is not set and environment is production-like
  try {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  } catch {}
  const prevEnv = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.env as any).SECURITY_KIT_ALLOW_TEST_APIS = undefined;

  // Temporarily set explicit environment to production to force guard
  const env = await import('../../src/environment');
  env.environment.setExplicitEnv('production');

  let threw = false;
  try {
    const postMessage = await import('../../src/postMessage');
    // This should throw because test APIs are disallowed in production
    (postMessage as any).__test_resetForUnitTests();
  } catch (err) {
    threw = true;
    expect((err as Error).message).toContain('Test-only APIs are disabled');
  }
  expect(threw).toBe(true);

  // restore environment for tests
  env.environment.setExplicitEnv('development');
  if (typeof prevEnv === 'undefined') delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  else process.env.SECURITY_KIT_ALLOW_TEST_APIS = prevEnv;
});

test('__test accessors succeed when global allow flag is set', async () => {
  vi.resetModules();
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    const postMessage = await import('../../src/postMessage');
    // These should not throw now
    await (postMessage as any).__test_ensureFingerprintSalt();
    const maybe = (postMessage as any).__test_getSaltFailureTimestamp();
    expect(typeof maybe === 'undefined' || typeof maybe === 'number').toBe(true);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test('__test accessors succeed when process.env allows test APIs', async () => {
  vi.resetModules();
  const prev = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  try {
    process.env.SECURITY_KIT_ALLOW_TEST_APIS = 'true';
    const env = await import('../../src/environment');
    env.environment.setExplicitEnv('production');
    const postMessage = await import('../../src/postMessage');
    // should not throw
    await (postMessage as any).__test_ensureFingerprintSalt();
    const maybe = (postMessage as any).__test_getSaltFailureTimestamp();
    expect(typeof maybe === 'undefined' || typeof maybe === 'number').toBe(true);
  } finally {
    const env = await import('../../src/environment');
    env.environment.setExplicitEnv('development');
    if (typeof prev === 'undefined') delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    else process.env.SECURITY_KIT_ALLOW_TEST_APIS = prev;
  }
});
