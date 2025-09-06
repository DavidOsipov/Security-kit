import { describe, it, expect, beforeEach } from 'vitest';
import {
  strictDecodeURIComponent,
  encodeHostLabel,
  createSecureURL,
  getEffectiveSchemes,
} from '../../src/url';
import { configureUrlPolicy, setUrlHardeningConfig } from '../../src/config';
import { InvalidParameterError } from '../../src/errors';

describe('url.percent/IDNA/IPv6 adversarial tests', () => {
  beforeEach(() => {
    // ensure default policy is strict for tests unless explicitly changed
    configureUrlPolicy({ safeSchemes: ['https:'] });
  });

  it('strictDecodeURIComponent rejects malformed percent sequences', () => {
    const r1 = strictDecodeURIComponent('%E0%A4');
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.error).toBeInstanceOf(Error);

    const r2 = strictDecodeURIComponent('%GG');
    expect(r2.ok).toBe(false);
  });

  it('strictDecodeURIComponent enforces max length', () => {
    const long = '%41'.repeat(5000);
    const r = strictDecodeURIComponent(long);
    expect(r.ok).toBe(false);
  });

  it('rejects percent-decoding of invalid UTF-8 sequences in path when strict decoding enabled', () => {
    setUrlHardeningConfig({ validatePathPercentEncoding: true });
    const bad = 'https://example.com/%C0%AF';
    expect(() => createSecureURL(bad)).toThrowError(InvalidParameterError);
  });

  it('bracketed IPv6 with port is accepted when scheme allowed', () => {
    // allow http for this test explicitly
    configureUrlPolicy({ safeSchemes: ['http:', 'https:'] });
    const href = createSecureURL('http://[2001:db8::1]:8080/');
    expect(href).toContain('[2001:db8::1]');
    expect(href).toContain(':8080');
  });

  it('rejects bracketed IPv6 host with extra closing bracket or malformed port', () => {
    configureUrlPolicy({ safeSchemes: ['http:', 'https:'] });
    expect(() => createSecureURL('http://[::1]]:8080/')).toThrowError(InvalidParameterError);
    expect(() => createSecureURL('http://[::1]:notaport/')).toThrowError(InvalidParameterError);
  });

  it('encodeHostLabel throws when provided invalid idna library', () => {
    expect(() => encodeHostLabel('пример', undefined as any)).toThrow();
    // Provide a library that throws to simulate IDNA failure
    const failing = { toASCII: (s: string) => { throw new Error('boom'); } };
    expect(() => encodeHostLabel('пример', failing)).toThrow();
  });

  it('throws when encodeHostLabel fails for IDNA (non-ASCII without punycode) and rejects by default', () => {
    // Some hosts with raw non-ASCII should be rejected; calling with a Cyrillic label
    expect(() => createSecureURL('https://пример.рф/')).toThrowError(InvalidParameterError);
  });

  it('allows IDNA when caller intentionally provides an already-punycode host', () => {
    // punycode form of пример.рф is xn--e1afmkfd.xn--p1ai (approx)
    const puny = 'https://xn--e1afmkfd.xn--p1ai/';
    const href2 = createSecureURL(puny);
    expect(href2).toContain('xn--');
  });

  it('getEffectiveSchemes intersection respects policy and rejects empty intersection', () => {
    // policy currently ['https:'] from beforeEach
    expect(() => getEffectiveSchemes(['http:'])).toThrowError(InvalidParameterError);
  });
});
