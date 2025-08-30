import { describe, it, expect, beforeEach } from 'vitest';
import { setHandshakeConfig, freezeConfig } from '../../src/config';
import { __test_resetCryptoStateForUnitTests } from '../../src/state';

describe('handshake config validation', () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === 'function') {
      __test_resetCryptoStateForUnitTests();
    }
  });

  it('accepts valid handshakeMaxNonceLength', () => {
    setHandshakeConfig({ handshakeMaxNonceLength: 64 });
    // no throw
  });

  it('rejects non-integer handshakeMaxNonceLength', () => {
    let threw = false;
    try {
      // @ts-expect-error: intentionally passing invalid type
      setHandshakeConfig({ handshakeMaxNonceLength: 3.14 });
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('rejects non-positive handshakeMaxNonceLength', () => {
    let threw = false;
    try {
      setHandshakeConfig({ handshakeMaxNonceLength: 0 });
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('accepts valid allowedNonceFormats array', () => {
    setHandshakeConfig({ allowedNonceFormats: ['hex', 'base64'] as any });
  });

  it('rejects empty allowedNonceFormats array', () => {
    let threw = false;
    try {
      setHandshakeConfig({ allowedNonceFormats: [] as any });
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('rejects non-string elements in allowedNonceFormats', () => {
    let threw = false;
    try {
      setHandshakeConfig({ allowedNonceFormats: [123 as any] });
    } catch (err) {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
