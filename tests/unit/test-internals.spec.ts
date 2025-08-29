import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import * as testInternals from '../../src/test-internals';
import { environment } from '../../src/environment';
import { InvalidConfigurationError } from '../../src/errors';

describe('test-internals guards', () => {
  let origEnv: any;
  let origNodeEnv: any;
  beforeEach(() => {
    origEnv = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    origNodeEnv = process.env.NODE_ENV;
    delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    // ensure global flag cleared
    try {
      // @ts-ignore
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    } catch {
      // ignore
    }
    // clear cached environment detection so subsequent changes take effect
    environment.clearCache();
  });
  afterEach(() => {
    if (origEnv !== undefined) process.env.SECURITY_KIT_ALLOW_TEST_APIS = origEnv;
    if (origNodeEnv !== undefined) process.env.NODE_ENV = origNodeEnv;
    else delete process.env.NODE_ENV;
    // restore/clear any cached environment detection
    environment.clearCache();
  });

  it('throws when environment disallows test APIs in production mode', () => {
    // Simulate production by setting NODE_ENV and clearing cache so the
    // environment detection recomputes from process.env.
    process.env.NODE_ENV = 'production';
    environment.clearCache();
    expect(() => testInternals.toNullProtoTest({})).toThrow(InvalidConfigurationError);
  });

  it('allows when global flag set', async () => {
    // set permissive global
    // @ts-ignore
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    // also ensure we are in a production-like environment to exercise the
    // guard code path that checks the global flag
    process.env.NODE_ENV = 'production';
    environment.clearCache();
    // should not throw
    expect(() => testInternals.toNullProtoTest({ a: 1 })).not.toThrow();
    // getPayloadFingerprintTest returns a promise
    await expect(testInternals.getPayloadFingerprintTest({ foo: 'bar' })).resolves.toBeTypeOf('string');
  });
});
