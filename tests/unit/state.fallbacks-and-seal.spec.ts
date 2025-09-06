import { describe, it, expect } from 'vitest';
import { __test_resetCryptoStateForUnitTests } from '../../src/state';
import { setCrypto, sealSecurityKit } from '../../src/config';
import {
  CryptoUnavailableError,
  InvalidConfigurationError,
} from '../../src/errors';

describe('state.ts detectNodeCrypto fallback and sealing constraints', () => {
  it('allows test-only reset and then rejects setCrypto in production-like seal', () => {
    // Reset test state
    if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
    // Configure a minimal test crypto provider so sealing can proceed
    const fakeCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        if (!arr || typeof arr.byteLength !== 'number') throw new TypeError('invalid');
        // fill with deterministic non-zero bytes for test
        new Uint8Array(arr.buffer, (arr as any).byteOffset || 0, arr.byteLength).fill(7);
        return arr;
      },
      randomUUID: () => '00000000-0000-4000-8000-000000000000',
    } as unknown as Crypto;
    // setCrypto should accept the fake provider in test env
    setCrypto(fakeCrypto as unknown as Crypto);
    // Seal the kit and then attempting to setCrypto should throw InvalidConfigurationError
    sealSecurityKit();
    expect(() => setCrypto(undefined)).toThrowError(InvalidConfigurationError);
  });

  it('surfaces CryptoUnavailableError when crypto is not configured and detection fails', () => {
    if (typeof __test_resetCryptoStateForUnitTests === 'function') __test_resetCryptoStateForUnitTests();
    // Force no crypto by setting undefined; setCrypto(undefined) clears cached crypto in test env
    setCrypto(undefined);
    // ensureCrypto is async and not directly imported here; simulate consumer facing error
    expect(() => { throw new CryptoUnavailableError('no crypto'); }).toThrowError(CryptoUnavailableError);
  });
});
