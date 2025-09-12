import { describe, it, expect } from 'vitest';
import { parseURLParams, normalizeOrigin, validateURL } from '../../src/url';

describe('url hardening extra tests', () => {
  it('parseURLParams result has null prototype and non-writable properties', () => {
    const res = parseURLParams('https://example.com/?a=1&b=2');
    expect(Object.getPrototypeOf(res)).toBeNull();
    const descA = Object.getOwnPropertyDescriptor(res, 'a');
    expect(descA).toBeDefined();
    expect(descA?.writable).toBe(false);
    expect(res.a).toBe('1');
  });

  it('normalizeOrigin omits default ports and retains custom ports', () => {
    expect(normalizeOrigin('https://example.com:443')).toBe('https://example.com');
    expect(normalizeOrigin('http://example.com:80')).toBe('http://example.com');
    expect(normalizeOrigin('https://example.com:8443')).toBe('https://example.com:8443');
  });

  it('percent-encoding regex validation behaves as expected after adding /u', () => {
    const ok = validateURL('https://example.com/%20');
    expect(ok.ok).toBe(true);
    const bad = validateURL('https://example.com/%2');
    expect(bad.ok).toBe(false);
  });

  it('dangerous keys from URLSearchParams are filtered and do not pollute result', () => {
    const url = 'https://example.com/?__proto__=polluted&constructor=bad&good=ok';
    const parsed = parseURLParams(url) as Record<string, string>;
    expect(parsed.__proto__).toBeUndefined();
    expect(parsed.constructor).toBeUndefined();
    expect(parsed.good).toBe('ok');
  });
});
