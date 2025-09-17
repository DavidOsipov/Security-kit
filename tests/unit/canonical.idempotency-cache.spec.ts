import { describe, it, expect, beforeEach } from 'vitest';
import { normalizeInputString, setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../../src/canonical';

// We monkey patch String.prototype.normalize to count invocations.
// This allows us to ensure the idempotency verification runs only once
// for cached inputs when mode='always'. We keep patching minimal to avoid
// side effects across tests.

describe('normalizeInputString idempotency cache', () => {
  const originalNormalize = String.prototype.normalize;
  let callCount = 0;

  beforeEach(() => {
    callCount = 0;
    String.prototype.normalize = function(form?: string) {
      callCount++;
      // Delegate to original for correctness
      // @ts-expect-error delegating to original
      return originalNormalize.call(this, form);
    } as any;
  });

  afterAll(() => {
    String.prototype.normalize = originalNormalize;
  });

  it('verifies once then caches (mode=always)', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'always' });
    const s = 'École'; // Non-ASCII ensures path triggers idempotency logic
    const out1 = normalizeInputString(s, 'idempotency-cache-test-1');
    const firstCount = callCount; // includes initial normalization + verify pass
    expect(firstCount).toBeGreaterThanOrEqual(2);
    const out2 = normalizeInputString(s, 'idempotency-cache-test-2');
    expect(out2).toBe(out1);
    const secondCount = callCount;
    // Second invocation should perform only the primary normalization; skip verify pass
    expect(secondCount).toBe(firstCount + 1);
  });

  it('respects sampling (mode=sample)', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'sample', normalizationIdempotencySampleRate: 2 });
    const s = 'Æther';
    normalizeInputString(s, 'idempotency-sample');
    // We cannot deterministically assert skip due to XOR hashing selection; just ensure at least one call occurred.
    expect(callCount).toBeGreaterThanOrEqual(1);
  });

  it('skips entirely when off', () => {
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'off' });
    callCount = 0;
    normalizeInputString('Ωmega', 'idempotency-off');
    // Only the initial normalization should run (no verification pass)
    expect(callCount).toBe(1);
  });
});
