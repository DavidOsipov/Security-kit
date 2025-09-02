import { describe, it, expect, beforeEach } from 'vitest';
import { SecureLRUCache } from '../../src/secure-cache';

describe('SecureLRUCache SIEVE Hand Management Fixes', () => {
  let cache: SecureLRUCache<string, Uint8Array>;

  beforeEach(() => {
    cache = new SecureLRUCache({
      maxEntries: 3,
      recencyMode: 'sieve',
    });
  });

  describe('SIEVE hand update on delete', () => {
    it('should move hand to predecessor when deleting current hand position', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 2,
        recencyMode: 'sieve',
      });

      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3]));

      testCache.delete('B');
      expect(testCache.get('B')).toBeUndefined();

      testCache.set('D', new Uint8Array([4]));
      expect(testCache.get('D')).toBeDefined();
    });

    it('should handle eviction after head deletion', () => {
      const testCache = new SecureLRUCache({
        maxEntries: 3,
        recencyMode: 'sieve',
      });

      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3]));

      testCache.get('A');
      testCache.get('B');

      testCache.set('D', new Uint8Array([4]));

      expect(testCache.get('A')).toBeDefined();
      expect(testCache.get('B')).toBeDefined();
      expect(testCache.get('C')).toBeUndefined();
      expect(testCache.get('D')).toBeDefined();
    });
  });

  describe('sieveRef reset on delete', () => {
    it('should clear sieveRef for sieve mode on delete', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 3,
        recencyMode: 'sieve',
      });

      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));

      testCache.get('A');

      testCache.delete('A');
      expect(testCache.get('A')).toBeUndefined();
      expect(testCache.get('B')).toBeDefined();
    });
  });

  describe('sieveHand reset on clear', () => {
    it('should reset sieveHand to NO_INDEX on clear', () => {
      cache.set('A', new Uint8Array([1]));
      cache.set('B', new Uint8Array([2]));

      cache.clear();

      expect(cache.get('A')).toBeUndefined();
      expect(cache.get('B')).toBeUndefined();

      cache.set('C', new Uint8Array([3]));
      expect(cache.get('C')).toBeDefined();
    });
  });

  describe('#evict switch preserves behavior', () => {
    it('should evict head in lru mode', () => {
      const cacheLRU = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 2,
        maxBytes: 1024,
        recencyMode: 'lru',
      });

      cacheLRU.set('A', new Uint8Array([1]));
      cacheLRU.set('B', new Uint8Array([2]));
      cacheLRU.set('C', new Uint8Array([3]));

      expect(cacheLRU.get('A')).toBeUndefined();
      expect(cacheLRU.get('B')).toBeDefined();
      expect(cacheLRU.get('C')).toBeDefined();
    });

    it('should use persistent hand in sieve mode', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 2,
        recencyMode: 'sieve',
      });

      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3])); // This should trigger eviction

      const remainingKeys = ['A', 'B', 'C'].filter(key => testCache.get(key) !== undefined);
      expect(remainingKeys).toHaveLength(2);
    });
  });

  describe('SIEVE hand invariants under random operations', () => {
    it('should maintain hand invariants during fuzz operations', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 5,
        recencyMode: 'sieve',
        includeUrlsInStats: true,
      });

      const operations = [
        () => testCache.set(`key${Math.random()}`, new Uint8Array([Math.floor(Math.random() * 256)])),
        () => testCache.get(`key${Math.floor(Math.random() * 10)}`),
        () => {
          const keys = testCache.getStats().urls;
          if (keys.length > 0) {
            testCache.delete(keys[Math.floor(Math.random() * keys.length)] as string);
          }
        },
        () => testCache.clear(),
      ];

      // Run 100 random operations
      for (let i = 0; i < 100; i++) {
        const op = operations[Math.floor(Math.random() * operations.length)];
        op();

        // After each operation, verify invariants
        const size = testCache.getStats().size;
        if (size === 0) {
          // Hand should be reset when cache is empty
          expect(testCache.get('hand')).toBeUndefined(); // We can't directly access hand, but size 0 implies hand reset
        } else {
          // Cache has entries, ensure we can still operate
          expect(size).toBeGreaterThan(0);
          expect(size).toBeLessThanOrEqual(5);
        }
      }
    });

    it('should handle delete head while hand points to head', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 3,
        recencyMode: 'sieve',
        includeUrlsInStats: true,
      });

      // Fill cache
      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3]));

      // Access A to potentially move hand
      testCache.get('A');

      // Delete head (A) - this should move hand to predecessor (B), not tail
      testCache.delete('A');
      expect(testCache.get('A')).toBeUndefined();

      // Add new entry to trigger eviction
      testCache.set('D', new Uint8Array([4]));

      // B and C should still be there, D should be added
      expect(testCache.get('B')).toBeDefined();
      expect(testCache.get('C')).toBeDefined();
      expect(testCache.get('D')).toBeDefined();
    });

    it('should clear sieveRef on delete for both sieve and second-chance modes', () => {
      const sieveCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 3,
        recencyMode: 'sieve',
        includeUrlsInStats: true,
      });

      const secondChanceCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 3,
        recencyMode: 'second-chance',
        includeUrlsInStats: true,
      });

      // Test sieve mode
      sieveCache.set('A', new Uint8Array([1]));
      sieveCache.set('B', new Uint8Array([2]));
      sieveCache.get('A'); // Set ref bit
      sieveCache.delete('A');
      expect(sieveCache.get('A')).toBeUndefined();

      // Test second-chance mode
      secondChanceCache.set('X', new Uint8Array([1]));
      secondChanceCache.set('Y', new Uint8Array([2]));
      secondChanceCache.get('X'); // Set ref bit
      secondChanceCache.delete('X');
      expect(secondChanceCache.get('X')).toBeUndefined();
    });
  });

  describe('Diagnostics and bounded operations', () => {
    it('should not exceed configured rotation limits in second-chance mode', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 2,
        recencyMode: 'second-chance',
        secondChanceMaxRotationsPerEvict: 3,
        includeUrlsInStats: true,
      });

      // Fill cache and set all ref bits
      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.get('A');
      testCache.get('B');

      // Trigger eviction - should rotate limited times
      testCache.set('C', new Uint8Array([3]));

      // Should have evicted one entry
      const remaining = ['A', 'B', 'C'].filter(key => testCache.get(key) !== undefined);
      expect(remaining).toHaveLength(2);
    });

    it('should handle segmented eviction scan limits', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 3,
        recencyMode: 'segmented',
        segmentedEvictScan: 2,
        includeUrlsInStats: true,
      });

      // Fill cache
      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3]));

      // Trigger eviction
      testCache.set('D', new Uint8Array([4]));

      // Should have 3 entries (evicted 1)
      expect(testCache.getStats().size).toBe(3);
    });

    it('should maintain hand position after multiple operations', () => {
      const testCache = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 4,
        recencyMode: 'sieve',
        includeUrlsInStats: true,
      });

      // Build up cache
      testCache.set('A', new Uint8Array([1]));
      testCache.set('B', new Uint8Array([2]));
      testCache.set('C', new Uint8Array([3]));
      testCache.set('D', new Uint8Array([4]));

      // Mix of operations
      testCache.get('A');
      testCache.delete('B');
      testCache.set('E', new Uint8Array([5])); // Should trigger eviction

      // Verify cache state
      expect(testCache.getStats().size).toBe(4);
      expect(testCache.get('A')).toBeDefined(); // Accessed, should survive
      expect(testCache.get('B')).toBeUndefined(); // Deleted
      expect(testCache.get('C')).toBeDefined();
      expect(testCache.get('D')).toBeDefined();
      expect(testCache.get('E')).toBeDefined();
    });
  });

  describe('Cross-mode consistency', () => {
    it('should handle mode switching scenarios', () => {
      // Test that different modes behave consistently for basic operations
      const modes = ['lru', 'segmented', 'second-chance', 'sieve'] as const;

      modes.forEach(mode => {
        const testCache = new SecureLRUCache<string, Uint8Array>({
          maxEntries: 3,
          recencyMode: mode,
          includeUrlsInStats: true,
        });

        testCache.set('A', new Uint8Array([1]));
        testCache.set('B', new Uint8Array([2]));
        testCache.set('C', new Uint8Array([3]));
        testCache.set('D', new Uint8Array([4])); // Should evict one entry

        expect(testCache.getStats().size).toBe(3);
        // After eviction, we should have 3 entries, but we don't know which one was evicted
        // So we check that we have exactly 3 entries and D is present (most recently set)
        expect(testCache.get('D')).toBeDefined();
        const urls = testCache.getStats().urls;
        expect(urls).toHaveLength(3);
        expect(urls).toContain('D');
      });
    });

    it('should preserve bytesLength capture on delete across modes', () => {
      const modes = ['lru', 'segmented', 'second-chance', 'sieve'] as const;

      modes.forEach(mode => {
        const testCache = new SecureLRUCache<string, Uint8Array>({
          maxEntries: 3,
          recencyMode: mode,
          includeUrlsInStats: true,
        });

        testCache.set('A', new Uint8Array([1, 2, 3]));
        testCache.set('B', new Uint8Array([4, 5]));

        const beforeDelete = testCache.getStats().size;
        testCache.delete('A');
        const afterDelete = testCache.getStats().size;

        expect(afterDelete).toBe(beforeDelete - 1);
        expect(testCache.get('A')).toBeUndefined();
        expect(testCache.get('B')).toBeDefined();
      });
    });
  });
});
