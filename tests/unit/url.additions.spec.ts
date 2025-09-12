import { describe, it, expect } from 'vitest';
import {
  encodeHostLabel,
  strictDecodeURIComponentOrThrow,
  // internal helpers are tested via public API where possible
  createSecureURL,
  validateURL,
  enforceSchemeAndLength as _enforceSchemeAndLength,
} from '../../src/url';
import { InvalidParameterError } from '../../src/errors';

describe('url.ts targeted additions for uncovered branches', () => {
  it('encodeHostLabel throws if idna library missing', () => {
    expect(() => encodeHostLabel('example', undefined as any)).toThrow(
      InvalidParameterError,
    );
  });

  it('encodeHostLabel throws when idna library toASCII throws', () => {
    const lib = { toASCII: (s: string) => { throw new Error('boom'); } };
    expect(() => encodeHostLabel('exämple', lib as any)).toThrow(
      InvalidParameterError,
    );
  });

  it('strictDecodeURIComponentOrThrow throws on malformed input', () => {
    expect(() => strictDecodeURIComponentOrThrow('%GZ')).toThrow(
      InvalidParameterError,
    );
  });

  it('preValidateBracketedIPv6Authority rejects missing bracket in host', () => {
    // exercise via validateURL which calls preValidateAuthority internals
    const res = validateURL('http://[::1'); // missing closing bracket
    expect(res.ok).toBe(false);
  });

  it('validateURL rejects IPv4 octet out of range', () => {
    const res = validateURL('http://256.1.1.1');
    expect(res.ok).toBe(false);
  });

  it('enforceSchemeAndLength detects dangerous scheme and maxLength', () => {
    // enforceSchemeAndLength is internal; exercise via validateURL which uses it
    const res1 = validateURL('javascript:alert(1)');
    expect(res1.ok).toBe(false);

    const long = 'https://example.com/' + 'a'.repeat(2000);
    const res2 = validateURL(long, { maxLength: 10 });
    expect(res2.ok).toBe(false);
  });
});
