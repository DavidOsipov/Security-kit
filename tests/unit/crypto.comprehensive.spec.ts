import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as state from '../../src/state';
import { secureRandomBytes, ensureCrypto, ensureCryptoSync, isCryptoAvailable, getInternalTestUtilities, __resetCryptoStateForTests, __test_getCachedCrypto, getCryptoState, CryptoState } from '../../src/state';
import { CryptoUnavailableError, InvalidParameterError } from '../../src/errors';
import { makeDeterministicStub } from './_test-helpers/crypto-stubs';

describe('Comprehensive crypto tests', () => {
  beforeEach(() => {
    // Ensure test-only reset helper is used when available
    try {
      __resetCryptoStateForTests();
    } catch {}
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('ensureCryptoSync throws when async init is required', () => {
    // Make sure no global crypto is present
    const original = (globalThis as any).crypto;
    delete (globalThis as any).crypto;

    try {
      expect(() => ensureCryptoSync()).toThrow(CryptoUnavailableError);
    } finally {
      if (original) (globalThis as any).crypto = original;
    }
  });

  it('sealing without crypto fails and sealing after init succeeds', async () => {
    // Reset and ensure sealed precondition
    __resetCryptoStateForTests();

    // Attempt to seal before crypto available
    await expect(async () => state._sealSecurityKit()).rejects.toThrow(CryptoUnavailableError);

    // Provide a deterministic stub via setCrypto path
    const stub = makeDeterministicStub([7]);
    // Use internal setter: import config setter
    const configModule = await import('../../src/config');
    (configModule as any).setCrypto(stub as any);

    // Now sealing should succeed
    expect(getCryptoState()).toBe(CryptoState.Configured);
    state._sealSecurityKit();
    expect(getCryptoState()).toBe(CryptoState.Sealed);

    // After sealing, ensureCrypto still returns the cached provider
    const c = await ensureCrypto();
    expect(c).toBeDefined();
  });

  it('concurrent secureRandomBytes calls do not race and return correct lengths', async () => {
    // Mock global crypto to deterministic stub
    const original = (globalThis as any).crypto;
    (globalThis as any).crypto = makeDeterministicStub([0x1, 0x2, 0x3]);
    __resetCryptoStateForTests();

    try {
      const tasks = Array.from({ length: 10 }, (_, i) => secureRandomBytes(i + 1));
      const results = await Promise.all(tasks);
      results.forEach((r, idx) => {
        expect(r).toBeInstanceOf(Uint8Array);
        expect(r.length).toBe(idx + 1);
        expect(r[0]).toBe(1); // deterministic stub fills with 1
      });
    } finally {
      if (original) (globalThis as any).crypto = original;
    }
  });

  it('internal test utilities expose generation and state under __TEST__', () => {
    const utils = getInternalTestUtilities();
    // Under test build this should be available
    if (!utils) {
      // Running outside test harness; skip assertion
      return;
    }
    expect(typeof utils._getCryptoGenerationForTest).toBe('function');
    expect(typeof utils._getCryptoStateForTest).toBe('function');
    // Initial state
    expect(utils._getCryptoStateForTest()).toBe(CryptoState.Unconfigured);
    expect(utils._getCryptoGenerationForTest()).toBeGreaterThanOrEqual(0);
  });

  it('exposes cached crypto via __test_getCachedCrypto when allowed', async () => {
    __resetCryptoStateForTests();
    // Mock global crypto
    const original = (globalThis as any).crypto;
    (globalThis as any).crypto = makeDeterministicStub([9]);

    try {
      // Ensure async init populates cache
      await ensureCrypto();
      const cached = typeof __test_getCachedCrypto === 'function' ? __test_getCachedCrypto() : undefined;
      // If the test-only accessor is unavailable (no __TEST__ flag), fall back to checking
      // that repeated calls to ensureCrypto return the same instance and behave correctly.
      const primary = await ensureCrypto();
      if (typeof cached === 'undefined') {
        const second = await ensureCrypto();
        expect(second).toBe(primary);
      } else {
        expect(cached).toBe(primary);
      }

      // Calling getRandomValues should not throw on the resolved provider
      const arr = new Uint8Array(4);
      ( (cached ?? primary) as Crypto).getRandomValues(arr);
      expect(arr[0]).toBe(9);
    } finally {
      if (original) (globalThis as any).crypto = original;
    }
  });

  it('secureRandomBytes rejects invalid inputs quickly', async () => {
    await expect(secureRandomBytes(-5)).rejects.toThrow(InvalidParameterError);
    await expect(secureRandomBytes(3.14)).rejects.toThrow(InvalidParameterError);
    await expect(secureRandomBytes(70000)).rejects.toThrow(InvalidParameterError);
  });
});
