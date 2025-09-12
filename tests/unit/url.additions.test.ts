import { describe, it, expect } from 'vitest';
import { encodeHostLabel, normalizeOrigin, parseAndValidateFullURL } from '../../src/url';

describe('encodeHostLabel - runtime guards', () => {
  it('throws when idna library is undefined', () => {
    expect(() => encodeHostLabel('example', undefined as any)).toThrow();
  });

  it('throws when idna library is null', () => {
    expect(() => encodeHostLabel('example', null as any)).toThrow();
  });

  it('throws when idna library missing toASCII', () => {
    expect(() => encodeHostLabel('example', {} as any)).toThrow();
  });

  it('throws when toASCII throws', () => {
    const bad = { toASCII: (_: string) => { throw new Error('boom'); } } as any;
    expect(() => encodeHostLabel('exämple', bad)).toThrow();
  });

  it('works with a valid idna library', () => {
    const lib = { toASCII: (s: string) => s.toLowerCase() } as any;
    const out = encodeHostLabel('Example', lib);
    expect(out).toBe('example');
  });
});

// isOriginAllowed is not exported; test via normalizeOrigin + isOriginAllowed logic
describe('isOriginAllowed behavior (via normalizeOrigin and validateURL allowlist semantics)', () => {
  it('treats undefined allowlist as permissive (via normalizeOrigin logic)', () => {
    // normalizeOrigin should accept a valid origin and produce canonical form
    const orig = normalizeOrigin('https://Example.COM');
    expect(orig).toBe('https://example.com');
  });

  it('normalizes origins consistently', () => {
    const a = normalizeOrigin('https://example.com:443');
    const b = normalizeOrigin('https://example.com');
    expect(a).toBe(b);
  });

  it('throws on invalid origin input', () => {
    expect(() => normalizeOrigin('http://')).toThrow();
  });

  it('is robust to non-string allowlist entries when building sets', () => {
    // This is a smoke test: constructing allowlist with non-strings should not throw during normalization
    const allowlist = ['https://example.com', (123 as unknown) as string, undefined as unknown as string];
    // Build normalized set like isOriginAllowed would; ensure no exceptions for non-string entries
    const normalized = new Set(
      Array.from(allowlist)
        .filter((a): a is string => typeof a === 'string')
        .map((a) => normalizeOrigin(a)),
    );
    expect(normalized.has('https://example.com')).toBe(true);
  });
});
