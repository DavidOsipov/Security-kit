import { describe, it, expect, beforeEach } from 'vitest';
import { normalizeInputString, setUnicodeSecurityConfig } from '../../src/canonical.ts';

// This test stresses the tiny 32-entry idempotency cache to ensure older entries
// are evicted and subsequently re-verified (incurs an extra normalization pass).
// We monkey patch normalize to count invocations globally.

describe('idempotency cache eviction', () => {
  const originalNormalize = String.prototype.normalize;
  let callCount = 0;
  beforeEach(() => {
    callCount = 0;
    String.prototype.normalize = function(form?: string) {
      callCount++;
      // @ts-expect-error delegate
      return originalNormalize.call(this, form);
    } as any;
    setUnicodeSecurityConfig({ normalizationIdempotencyMode: 'always' });
  });

  afterAll(() => {
    String.prototype.normalize = originalNormalize;
  });

  it('evicts earliest entries after exceeding capacity', () => {
    // Populate >32 distinct non-ASCII strings
    for (let i = 0; i < 40; i++) {
      normalizeInputString(`É-${i}`, 'evict-load');
    }
    const afterWarm = callCount;
    // Re-normalize first value; should perform both passes again because original fingerprint evicted.
    normalizeInputString('É-0', 'evict-recheck');
    const delta = callCount - afterWarm;
    expect(delta).toBeGreaterThanOrEqual(2); // at least initial + verify pass
  });
});
