import { describe, it, expect } from 'vitest';

import {
  encodeHostLabel,
  strictDecodeURIComponent,
  strictDecodeURIComponentOrThrow,
  createSecureURL,
  validateURL,
  getEffectiveSchemes,
} from '../../src/url';

import { InvalidParameterError } from '../../src/errors';

describe('url - extra hardening edgecases', () => {
  it('encodeHostLabel throws when no idna library provided', () => {
    expect(() => encodeHostLabel('example', undefined as any)).toThrow();
  });

  it('strictDecodeURIComponent returns error for overly long input', () => {
    const long = 'a'.repeat(5000);
    const res = strictDecodeURIComponent(long);
    expect(res.ok).toBe(false);
    expect(res.error).toBeInstanceOf(Error);
    expect(String(res.error.message).toLowerCase()).toContain('too');
  });

  it('strictDecodeURIComponentOrThrow throws on malformed input', () => {
    expect(() => strictDecodeURIComponentOrThrow('%')).toThrow();
  });

  it('createSecureURL preserves IPv4 shorthand hostnames in returned href', () => {
    // Do not pass caller allowedSchemes here: runtime policy may restrict schemes
    // and cause an intersection failure. Test should focus on IPv4 shorthand preservation.
  const href = createSecureURL('https://192.168.1');
    // Should preserve the shorthand 192.168.1 rather than normalizing to a full 4-octet form
    expect(href).toContain('192.168.1');
  });

  it('createSecureURL rejects authority containing percent-encoding', () => {
    expect(() => createSecureURL('http://exa%25mple.com', [], {}, undefined, {})).toThrow(InvalidParameterError);
  });

  it('createSecureURL rejects embedded credentials', () => {
    expect(() => createSecureURL('http://user:pass@example.com', [], {}, undefined, {})).toThrow(InvalidParameterError);
  });

  it('createSecureURL rejects multiple @ characters in authority', () => {
    expect(() => createSecureURL('http://a@b@c.com', [], {}, undefined, {})).toThrow(InvalidParameterError);
  });

  it('createSecureURL rejects invalid path segments like ..', () => {
    expect(() => createSecureURL('https://example.com', ['..'], {}, undefined, {})).toThrow(InvalidParameterError);
  });

  it('createSecureURL rejects dangerous query keys when onUnsafeKey=throw', () => {
    const m = new Map<string, unknown>([['__proto__', 'x']]);
    expect(() => createSecureURL('https://example.com', [], m as any, undefined, { onUnsafeKey: 'throw' as any })).toThrow(InvalidParameterError);
  });

  it('validateURL returns ok:false when allowedSchemes is empty (deny-all)', () => {
    const res = validateURL('https://example.com', { allowedSchemes: [] });
    expect(res.ok).toBe(false);
  });

  it('getEffectiveSchemes throws on non-intersecting caller list', () => {
    // Use a scheme that is extremely unlikely to be in the safe policy
    expect(() => getEffectiveSchemes(['gopher:'])).toThrow();
  });
});
