import { expect, test } from 'vitest';
import * as postMessage from '../../src/postMessage';

test('toNullProto and deepFreeze test helpers work when guard enabled', () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    const o = { a: 1, b: { c: 2 } } as any;
    const res = postMessage.__test_toNullProto(o);
    expect((res as any).a).toBe(1);

    const frozen = postMessage.__test_deepFreeze({ x: 1 });
    expect(Object.isFrozen(frozen)).toBe(true);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

import { environment } from '../../src/environment';

test('assertTestApiAllowedInline throws when not allowed in production', () => {
  // Ensure guard throws when the flag is not set and environment.isProduction is true.
  const orig = (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  try {
    // Ensure both the env flag and global flag are explicitly disabled so the
    // runtime guard cannot be bypassed by environment.
    const prevEnvFlag = process.env?.['SECURITY_KIT_ALLOW_TEST_APIS'];
    try {
      delete process.env['SECURITY_KIT_ALLOW_TEST_APIS'];
    } catch {}
    try {
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    } catch {}

    // Use explicit API to force production mode for this test.
    environment.setExplicitEnv('production');
    try {
      expect(() => (postMessage as any).__test_getSaltFailureTimestamp()).toThrow();
    } finally {
      // restore explicit environment setting
      try {
        environment.setExplicitEnv('development');
      } catch {}
      if (typeof prevEnvFlag !== 'undefined') process.env['SECURITY_KIT_ALLOW_TEST_APIS'] = prevEnvFlag;
    }
  } finally {
    if (typeof orig !== 'undefined') (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = orig;
  }
});
