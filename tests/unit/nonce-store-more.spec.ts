import { describe, it, expect, vi } from 'vitest';
import { InMemoryNonceStore as NonceStore } from '../../server/verify-api-request-signature';
import { withAdvancedDateNow } from '../helpers/advanceDateNow';

describe('NonceStore - edge cases', () => {
  it('returns false for unknown nonce and true after store', async () => {
    const s = new NonceStore();
    const kid = 'k1';
    const n = 'n1';
    expect(await s.has(kid, n)).toBe(false);
    await s.store(kid, n, 1000);
    expect(await s.has(kid, n)).toBe(true);
  });

  it('expires entries after TTL', async () => {
    const s = new NonceStore();
    const kid = 'k2';
    const n = 'n2';
    await s.store(kid, n, 10);
    expect(await s.has(kid, n)).toBe(true);
    const now = Date.now();
    await withAdvancedDateNow(now + 1000, async () => {
      expect(await s.has(kid, n)).toBe(false);
    });
  });
});
