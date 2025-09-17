import { describe, it, expect } from 'vitest';
import { normalizeUrlComponent, normalizeUrlSafeString } from '../../src/canonical.ts';
import { normalizeUrlComponentStrict, normalizeUrlSafeStringStrict } from '../../src/url.ts';
import { InvalidParameterError } from '../../src/errors.ts';

// Migration assurance tests: ensure deprecated wrappers behave identically to new strict helpers

describe('URL normalization migration', () => {
  it('component normalization parity (host)', () => {
    const legacy = normalizeUrlComponent('Example.COM', 'host');
    const modern = normalizeUrlComponentStrict('Example.COM', 'host');
    expect(legacy).toBe(modern);
    expect(modern).toBe('example.com');
  });

  it('component normalization parity (scheme)', () => {
    const legacy = normalizeUrlComponent('HtTp', 'scheme');
    const modern = normalizeUrlComponentStrict('HtTp', 'scheme');
    expect(legacy).toBe('http');
    expect(modern).toBe('http');
  });

  it('safe string parity', () => {
    const input = 'https://example.com/path?q=1';
    const legacy = normalizeUrlSafeString(input, 'url');
    const modern = normalizeUrlSafeStringStrict(input, 'url');
    expect(legacy).toBe(modern);
  });

  it('dangerous pattern rejection maintained', () => {
    expect(() => normalizeUrlSafeString('javascript:alert(1)', 'u')).toThrow(InvalidParameterError);
    expect(() => normalizeUrlSafeStringStrict('javascript:alert(1)', 'u')).toThrow(InvalidParameterError);
  });

  it('encoded traversal rejection parity in path component', () => {
    const evil = '%2e%2e/secret';
    expect(() => normalizeUrlComponent(evil, 'path')).toThrow(InvalidParameterError);
    expect(() => normalizeUrlComponentStrict(evil, 'path')).toThrow(InvalidParameterError);
  });
});
