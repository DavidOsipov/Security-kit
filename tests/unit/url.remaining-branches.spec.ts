import { describe, it, expect, beforeEach } from 'vitest';
import {
  parseAndValidateFullURL,
  encodeHostLabel,
  parseURLParams,
  strictDecodeURIComponent,
  strictDecodeURIComponentOrThrow,
  createSecureURL,
  validateURL,
} from '../../src/url';
import { setUrlHardeningConfig, runWithStrictUrlHardening, _resetUrlPolicyForTests } from '../../src/config';
import { InvalidParameterError } from '../../src/errors';

// NOTE: parseAndValidateFullURL is not exported from index; import path uses src/url directly
// but here we import via module path used by tests; the test harness allows it.

describe('url.remaining-branches - IDNA, IPv6, forbidden chars, port/colon, percent-encoding', () => {
  beforeEach(() => {
    _resetUrlPolicyForTests();
    // Start from permissive dev defaults
    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: false, forbidForbiddenHostCodePoints: true });
  });

  it('rejects raw non-ASCII in authority (IDNA required)', () => {
    expect(() => createSecureURL('https://exámple.com')).toThrow(InvalidParameterError);
  });

  it('bracketed IPv6 authority is accepted and not rejected by colon rule', () => {
    const href = createSecureURL('https://[2001:0db8:85a3::8a2e:0370:7334]');
    expect(href).toContain('[');
    expect(href).toContain(']');
  });

  it('rejects authority when forbidden host code point present', () => {
    expect(() => createSecureURL('https://exa<mple.com')).toThrow(InvalidParameterError);
  });

  it('rejects invalid colon usage in authority (multiple colons without brackets)', () => {
    // This looks like host:port:bad which should be rejected
    expect(() => createSecureURL('https://host:80:90')).toThrow(InvalidParameterError);
  });

  it('percent-encoded sequences in path validated when enabled', () => {
    setUrlHardeningConfig({ validatePathPercentEncoding: true });
    expect(() => createSecureURL('https://example.com/%GG', ['a'])).toThrow(InvalidParameterError);
  });

  it('strict hardening preserves IPv4-shorthand via Proxy hostname read', () => {
    // In permissive (dev) mode, shorthand should be preserved
    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: false });
    const href = createSecureURL('https://192.168.1');
    expect(href).toContain('192.168.1');
  });

  it('strict hardening rejects IPv4-shorthand as ambiguous', () => {
    // With strict checks enabled, shorthand must be rejected
    runWithStrictUrlHardening(() => {
      expect(() => createSecureURL('https://192.168.1')).toThrow(InvalidParameterError);
    });
  });

  it('strictDecodeURIComponent returns error on control-chars after decode', () => {
    const res = strictDecodeURIComponent('%00');
    expect(res.ok).toBe(false);
  });
});
