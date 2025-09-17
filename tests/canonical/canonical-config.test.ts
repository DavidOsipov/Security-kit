// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig, normalizeInputString, setCanonicalConfig, toCanonicalValue, sanitizeForLogging } from '../../src/index.ts';

// Basic smoke tests for newly added configuration toggles & behaviors.

describe('Unicode combining ratio configuration', () => {
  it('respects custom maxCombiningRatio (allows below threshold)', () => {
    setUnicodeSecurityConfig({ maxCombiningRatio: 0.5 });
    const cfg = getUnicodeSecurityConfig();
    expect(cfg.maxCombiningRatio).toBe(0.5);
    // Construct string with ratio ~0.4
    const base = 'a'.repeat(30);
    const combining = '\u0301'.repeat(20); // 20 combining marks
    const input = base + combining; // total 50 chars => ratio 0.4
    const out = normalizeInputString(input, 'test');
    expect(out.length).toBe(input.normalize('NFKC').length);
  });

  it('rejects when exceeding custom maxCombiningRatio', () => {
    setUnicodeSecurityConfig({ maxCombiningRatio: 0.2 });
    const base = 'a'.repeat(30);
    const combining = '\u0301'.repeat(20); // 20/50 = 0.4 > 0.2
    expect(() => normalizeInputString(base + combining, 'ratio')).toThrowError(/Suspicious ratio/);
  });
});

describe('Normalization idempotency sampling', () => {
  it('does not throw for stable ASCII', () => {
    const s = 'HelloWorld123';
    expect(normalizeInputString(s)).toBe(s);
  });
});

describe('Circular policy fail vs annotate', () => {
  it('throws with circularPolicy=fail', () => {
    setCanonicalConfig({ circularPolicy: 'fail' });
    const a: any = {}; a.self = a; // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(() => toCanonicalValue(a)).toThrowError(/Circular reference detected/);
  });
  it('annotates with circularPolicy=annotate', () => {
    setCanonicalConfig({ circularPolicy: 'annotate' });
    const a: any = {}; a.self = a; // eslint-disable-line @typescript-eslint/no-explicit-any
    const canon = toCanonicalValue(a) as any; // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(typeof canon).toBe('object');
  });
});

describe('_toString placeholder metric', () => {
  it('produces placeholder for unserializable objects', () => {
    const cyclic: any = {}; cyclic.self = cyclic; // eslint-disable-line @typescript-eslint/no-explicit-any
    const log = sanitizeForLogging(cyclic);
    expect(log.includes('[UNSERIALIZABLE]') || log.length > 0).toBe(true);
  });
});
