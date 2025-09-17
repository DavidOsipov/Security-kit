// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { setUnicodeSecurityConfig, normalizeInputString } from '../../src/index.ts';

// We use crafted strings that are already NFKC stable; validation should pass regardless of mode.
// Difficult to deterministically force an idempotency failure without monkey patching normalize; here we assert no regression.

describe('normalization idempotency modes', () => {
  const sample = 'Ångström'; // includes combining-like char after normalization but stable
  it('mode=off skips verification', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'off' });
    expect(normalizeInputString(sample)).toBe(sample.normalize('NFKC'));
  });
  it('mode=always performs verification (no throw for stable input)', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'always' });
    expect(normalizeInputString(sample)).toBe(sample.normalize('NFKC'));
  });
  it('mode=sample does not throw (sampling cannot be asserted deterministically here)', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'sample', normalizationIdempotencySampleRate: 2 });
    expect(normalizeInputString(sample)).toBe(sample.normalize('NFKC'));
  });
});
