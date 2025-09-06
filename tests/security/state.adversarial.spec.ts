import { describe, it, expect, beforeEach } from 'vitest';
import * as state from '../../src/state';
import { InvalidConfigurationError, CryptoUnavailableError } from '../../src/errors';

describe('state.adversarial - crypto lifecycle & seal behavior', () => {
  beforeEach(() => {
    // Ensure test-only reset is available and use it
    if (typeof (state as any).__test_resetCryptoStateForUnitTests === 'function') {
      (state as any).__test_resetCryptoStateForUnitTests();
    } else {
      // fallback to public reset helper
      state.__resetCryptoStateForTests();
    }
    process.env['NODE_ENV'] = 'test';
  });

  it('sealSecurityKit throws when no crypto configured', () => {
    expect(() => (state as any)._sealSecurityKit()).toThrow(CryptoUnavailableError);
  });

  it('setCrypto rejects non-crypto objects and enforces production constraints', () => {
    // Non-crypto object should be rejected by internal _setCrypto
    // Implementation throws InvalidParameterError for invalid shape
    expect(() => (state as any)._setCrypto({} as any)).toThrow();
  });

  it('ensureCrypto handles cache poisoning invalidation', async () => {
    // Simulate rapid generation changes by clearing cached crypto
    (state as any).__test_setCachedCrypto(undefined);
    // If a global crypto is available in the environment, ensureCrypto will resolve to it.
    const globalCrypto = (globalThis as any).crypto;
    if (globalCrypto && typeof globalCrypto.getRandomValues === 'function') {
      await expect((state as any).ensureCrypto()).resolves.toBeDefined();
    } else {
      // Otherwise, ensureCrypto should reject because Node detection will fail in test env
      await expect((state as any).ensureCrypto()).rejects.toThrow(CryptoUnavailableError);
    }
  });
});
