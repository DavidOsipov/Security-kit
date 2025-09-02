import { describe, it, expect } from 'vitest';
import { SecureLRUCache } from '../../src/secure-cache';

function makeBytes(n: number): Uint8Array {
  const u = new Uint8Array(8);
  u.fill(n & 0xff);
  return u;
}

describe('SecureLRUCache second-chance policy', () => {
  it('evicts one-hit-wonders first (new entries start unreferenced)', () => {
    const c = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 4,
      maxBytes: 10_000,
      recencyMode: 'second-chance',
      segmentedEvictScan: 4,
    });

    // Insert 4 entries, do not touch a,b,c; touch d to set visited
    c.set('a', makeBytes(1));
    c.set('b', makeBytes(2));
    c.set('c', makeBytes(3));
    c.set('d', makeBytes(4));
    // Access d so it gets referenced
    expect(c.get('d')).toBeDefined();

    // Insert e to trigger eviction. Second-chance should evict an unreferenced older entry: 'a'.
    c.set('e', makeBytes(5));
    expect(c.get('a')).toBeUndefined();
    // d should remain due to reference bit
    expect(c.get('d')).toBeDefined();
  });

  it('bounded rotations per eviction', () => {
    const c = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 3,
      maxBytes: 10_000,
      recencyMode: 'second-chance',
      segmentedEvictScan: 2,
      secondChanceMaxRotationsPerEvict: 1,
    });

    c.set('a', makeBytes(1));
    c.set('b', makeBytes(2));
    c.set('c', makeBytes(3));
    // Touch all so they are referenced
    c.get('a'); c.get('b'); c.get('c');

    // Next insert forces eviction; only 1 rotation allowed → still evicts head fallback deterministically
    c.set('d', makeBytes(4));
    // At least one of the earliest should be gone; exact victim depends on internal order
    const survivors = ['a','b','c'].filter(k => c.get(k) !== undefined);
    expect(survivors.length).toBeLessThan(3);
  });

  it('TTL expiry still enforced under second-chance', () => {
    const c = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 10_000,
      recencyMode: 'second-chance',
      defaultTtlMs: 1,
      ttlAutopurge: false,
    });
    c.set('x', makeBytes(1));
    // Busy-wait a tiny while; in Vitest timers are real by default in unit tests
    const start = Date.now();
    while (Date.now() - start < 2) { /* spin a tiny bit */ }
    expect(c.get('x')).toBeUndefined();
  });
});

describe('SecureLRUCache canonical SIEVE policy', () => {
  it('evicts unreferenced without pointer rotations (hand-based)', () => {
    const c = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 3,
      maxBytes: 10_000,
      recencyMode: 'sieve',
      segmentedEvictScan: 3,
    });

    c.set('a', makeBytes(1));
    c.set('b', makeBytes(2));
    c.set('c', makeBytes(3));
    // Touch b and c so they are referenced; leave a unreferenced
    expect(c.get('b')).toBeDefined();
    expect(c.get('c')).toBeDefined();

    // Insert d → eviction should prefer 'a' (unreferenced) without rotating nodes
    c.set('d', makeBytes(4));
    expect(c.get('a')).toBeUndefined();
  });
});
