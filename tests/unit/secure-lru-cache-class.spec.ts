import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SecureLRUCache, type CacheOptions, type EvictedEntry } from '../../src/secure-lru-cache';
import { InvalidParameterError } from '../../src/errors';

describe('SecureLRUCache (standalone class)', () => {
  let cache: SecureLRUCache<string, Uint8Array>;

  beforeEach(() => {
    cache = new SecureLRUCache({
      maxEntries: 3,
      maxBytes: 100,
      defaultTtlMs: 1000,
    });
  });

  describe('construction and validation', () => {
    it('creates cache with default options', () => {
      const defaultCache = new SecureLRUCache();
      const stats = defaultCache.getStats();
      expect(stats.size).toBe(0);
      expect(stats.totalBytes).toBe(0);
    });

    it('throws on invalid maxEntries', () => {
      expect(() => new SecureLRUCache({ maxEntries: 0 })).toThrow(TypeError);
      expect(() => new SecureLRUCache({ maxEntries: -1 })).toThrow(TypeError);
      expect(() => new SecureLRUCache({ maxEntries: 1.5 })).toThrow(TypeError);
    });

    it('throws on invalid maxBytes', () => {
      expect(() => new SecureLRUCache({ maxBytes: -1 })).toThrow(TypeError);
    });

    it('throws when freezeReturns is true but copyOnGet is false', () => {
      expect(() => new SecureLRUCache({ freezeReturns: true, copyOnGet: false })).toThrow(
        'freezeReturns` requires `copyOnGet` to be true'
      );
    });
  });

  describe('basic operations', () => {
    it('stores and retrieves values', () => {
      const key = 'test-key';
      const value = new Uint8Array([1, 2, 3]);
      
      cache.set(key, value);
      const retrieved = cache.get(key);
      
      expect(retrieved).toEqual(value);
      expect(retrieved).not.toBe(value); // Should be a copy by default
    });

    it('returns undefined for non-existent keys', () => {
      expect(cache.get('non-existent')).toBeUndefined();
    });

    it('deletes entries', () => {
      const key = 'test-key';
      const value = new Uint8Array([1, 2, 3]);
      
      cache.set(key, value);
      expect(cache.get(key)).toBeDefined();
      
      cache.delete(key);
      expect(cache.get(key)).toBeUndefined();
    });

    it('clears all entries', () => {
      cache.set('key1', new Uint8Array([1]));
      cache.set('key2', new Uint8Array([2]));
      
      expect(cache.getStats().size).toBe(2);
      
      cache.clear();
      expect(cache.getStats().size).toBe(0);
    });
  });

  describe('LRU behavior', () => {
    it('evicts least recently used entry when capacity is exceeded', () => {
      // Fill cache to capacity
      cache.set('key1', new Uint8Array([1]));
      cache.set('key2', new Uint8Array([2]));
      cache.set('key3', new Uint8Array([3]));
      
      // Access key1 to make it most recently used
      cache.get('key1');
      
      // Add another entry, should evict key2 (least recently used)
      cache.set('key4', new Uint8Array([4]));
      
      expect(cache.get('key1')).toBeDefined(); // Still there
      expect(cache.get('key2')).toBeUndefined(); // Evicted
      expect(cache.get('key3')).toBeDefined(); // Still there
      expect(cache.get('key4')).toBeDefined(); // New entry
    });

    it('updates existing entries without changing capacity', () => {
      cache.set('key1', new Uint8Array([1, 1]));
      cache.set('key2', new Uint8Array([2, 2]));
      
      const initialStats = cache.getStats();
      
      // Update existing entry
      cache.set('key1', new Uint8Array([1, 1, 1]));
      
      const updatedStats = cache.getStats();
      expect(updatedStats.size).toBe(initialStats.size); // Same number of entries
      expect(updatedStats.totalBytes).toBe(initialStats.totalBytes + 1); // One more byte
    });
  });

  describe('TTL functionality', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('expires entries after TTL', () => {
      cache.set('key1', new Uint8Array([1]));
      
      // Should be available immediately
      expect(cache.get('key1')).toBeDefined();
      
      // Advance time beyond TTL
      vi.advanceTimersByTime(1001);
      
      // Should be expired
      expect(cache.get('key1')).toBeUndefined();
    });

    it('uses custom TTL per entry', () => {
      cache.set('short', new Uint8Array([1]), { ttlMs: 100 });
      cache.set('long', new Uint8Array([2]), { ttlMs: 2000 });
      
      // Advance time to expire short-lived entry
      vi.advanceTimersByTime(150);
      
      expect(cache.get('short')).toBeUndefined();
      expect(cache.get('long')).toBeDefined();
    });

    it('handles zero TTL as no expiration', () => {
      cache.set('permanent', new Uint8Array([1]), { ttlMs: 0 });
      
      // Advance time way beyond default TTL
      vi.advanceTimersByTime(10000);
      
      expect(cache.get('permanent')).toBeDefined();
    });
  });

  describe('security features', () => {
    it('rejects SharedArrayBuffer views by default', () => {
      if (typeof SharedArrayBuffer !== 'undefined') {
        const sharedBuffer = new SharedArrayBuffer(10);
        const sharedView = new Uint8Array(sharedBuffer);
        
        expect(() => cache.set('shared', sharedView)).toThrow(InvalidParameterError);
      }
    });

    it('allows SharedArrayBuffer views when configured', () => {
      if (typeof SharedArrayBuffer !== 'undefined') {
        const permissiveCache = new SecureLRUCache({ rejectSharedBuffers: false });
        const sharedBuffer = new SharedArrayBuffer(10);
        const sharedView = new Uint8Array(sharedBuffer);
        
        expect(() => permissiveCache.set('shared', sharedView)).not.toThrow();
      }
    });

    it('freezeReturns attempts to freeze wrapper (typed arrays may not be freezable)', () => {
      const freezingCache = new SecureLRUCache({
        copyOnGet: true,
        freezeReturns: true,
      });

      const value = new Uint8Array([1, 2, 3]);
      freezingCache.set('key', value);

      const retrieved = freezingCache.get('key');
      expect(retrieved).toBeInstanceOf(Uint8Array);
      // In Node >= 18, Object.freeze on typed arrays throws; reflect environment capability
      const canFreezeTypedArray = (() => {
        try {
          const probe = new Uint8Array([1]);
          Object.freeze(probe);
          return Object.isFrozen(probe);
        } catch {
          return false;
        }
      })();
      expect(Object.isFrozen(retrieved)).toBe(canFreezeTypedArray);
    });

    it('performs defensive copying by default', () => {
      const original = new Uint8Array([1, 2, 3]);
      cache.set('key', original);
      
      // Mutate original
      original[0] = 99;
      
      // Cache should be unaffected
      const retrieved = cache.get('key');
      expect(retrieved?.[0]).toBe(1);
    });

    it('respects copyOnSet=false configuration', () => {
      const noCopyCache = new SecureLRUCache({ copyOnSet: false });
      const original = new Uint8Array([1, 2, 3]);
      
      noCopyCache.set('key', original);
      
      // Since no copy was made, mutation affects cached value
      original[0] = 99;
      
      const retrieved = noCopyCache.get('key');
      expect(retrieved?.[0]).toBe(99);
    });

    it('respects copyOnGet=false configuration', () => {
      const noCopyCache = new SecureLRUCache({ copyOnGet: false });
      const value = new Uint8Array([1, 2, 3]);
      
      noCopyCache.set('key', value);
      
      const retrieved1 = noCopyCache.get('key');
      const retrieved2 = noCopyCache.get('key');
      
      // Same reference returned
      expect(retrieved1).toBe(retrieved2);
    });
  });

  describe('validation and error handling', () => {
    it('throws on oversized entries', () => {
      const largeValue = new Uint8Array(1000); // Exceeds maxBytes: 100
      
      expect(() => cache.set('key', largeValue)).toThrow(InvalidParameterError);
    });

    it('throws on oversized keys', () => {
      const longKey = 'x'.repeat(3000); // Exceeds default maxUrlLength: 2048
      
      expect(() => cache.set(longKey, new Uint8Array([1]))).toThrow(InvalidParameterError);
    });

    it('throws on invalid key type', () => {
      expect(() => cache.set(123 as any, new Uint8Array([1]))).toThrow(InvalidParameterError);
    });

    it('throws on invalid value type', () => {
      expect(() => cache.set('key', 'not-uint8array' as any)).toThrow(InvalidParameterError);
    });

    it('respects per-operation maxEntryBytes override', () => {
      const value = new Uint8Array(50); // Smaller than default maxEntryBytes
      
      // Should succeed with higher limit
      expect(() => cache.set('key1', value, { maxEntryBytes: 100 })).not.toThrow();
      
      // Should fail with lower limit
      expect(() => cache.set('key2', value, { maxEntryBytes: 25 })).toThrow(InvalidParameterError);
    });
  });

  describe('eviction callbacks', () => {
    it('calls onEvict callback with correct information', async () => {
      const evictedEntries: EvictedEntry[] = [];
      const callbackCache = new SecureLRUCache({
        maxEntries: 2,
        onEvict: (entry) => evictedEntries.push(entry),
      });
      
      // Fill cache to capacity
      callbackCache.set('key1', new Uint8Array([1, 1]));
      callbackCache.set('key2', new Uint8Array([2, 2, 2]));
      
      // Force eviction
      callbackCache.set('key3', new Uint8Array([3]));
      // onEvict is dispatched asynchronously
      await Promise.resolve();

      expect(evictedEntries).toHaveLength(1);
      expect(evictedEntries[0]).toEqual({
        url: 'key1',
        bytesLength: 2,
        reason: 'capacity',
      });
    });

    it('calls onEvict for manual deletions', async () => {
      const evictedEntries: EvictedEntry[] = [];
      const callbackCache = new SecureLRUCache({
        onEvict: (entry) => evictedEntries.push(entry),
      });
      
      callbackCache.set('key1', new Uint8Array([1, 2]));
      callbackCache.delete('key1');
      // onEvict is dispatched asynchronously
      await Promise.resolve();

      expect(evictedEntries).toHaveLength(1);
      expect(evictedEntries[0].reason).toBe('manual');
    });

    it('handles errors in onEvict callback gracefully', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      const errorCache = new SecureLRUCache({
        maxEntries: 1,
        onEvict: () => { throw new Error('Callback error'); },
      });
      
      errorCache.set('key1', new Uint8Array([1]));
      errorCache.set('key2', new Uint8Array([2])); // Should trigger eviction
      // onEvict error is reported asynchronously
      await Promise.resolve();

      // Cache should still work despite callback error
      expect(errorCache.get('key2')).toBeDefined();
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      consoleErrorSpy.mockRestore();
    });
  });

  describe('statistics', () => {
    it('tracks cache statistics correctly', () => {
      const initialStats = cache.getStats();
      expect(initialStats.size).toBe(0);
      expect(initialStats.hits).toBe(0);
      expect(initialStats.misses).toBe(0);
      
      // Add some entries
      cache.set('key1', new Uint8Array([1, 2]));
      cache.set('key2', new Uint8Array([3, 4, 5]));
      
      // Test hits and misses
      cache.get('key1'); // hit
      cache.get('nonexistent'); // miss
      
      const stats = cache.getStats();
      expect(stats.size).toBe(2);
      expect(stats.totalBytes).toBe(5);
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
      expect(stats.setOps).toBe(2);
      expect(stats.getOps).toBe(2);
    });

    it('includes URLs in stats when configured', () => {
      const urlIncludingCache = new SecureLRUCache({ includeUrlsInStats: true });
      
      urlIncludingCache.set('key1', new Uint8Array([1]));
      urlIncludingCache.set('key2', new Uint8Array([2]));
      
      const stats = urlIncludingCache.getStats();
      expect(stats.urls).toContain('key1');
      expect(stats.urls).toContain('key2');
    });

    it('excludes URLs from stats by default', () => {
      cache.set('sensitive-url', new Uint8Array([1]));
      
      const stats = cache.getStats();
      expect(stats.urls).toEqual([]);
    });
  });

  describe('disabled cache behavior', () => {
    it('behaves as no-op when enableByteCache is false', () => {
      const disabledCache = new SecureLRUCache({ enableByteCache: false });
      
      disabledCache.set('key', new Uint8Array([1, 2, 3]));
      expect(disabledCache.get('key')).toBeUndefined();
      
      const stats = disabledCache.getStats();
      expect(stats.size).toBe(0);
    });
  });

  describe('high watermark cleanup', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('triggers cleanup when high watermark is exceeded', () => {
      const watermarkCache = new SecureLRUCache({
        maxEntries: 10,
        maxBytes: 1000,
        highWatermarkBytes: 50,
        defaultTtlMs: 100,
      });
      
      // Add entries that will expire
      watermarkCache.set('expire1', new Uint8Array(30), { ttlMs: 100 });
      watermarkCache.set('expire2', new Uint8Array(30), { ttlMs: 100 });
      
      // Advance time to make them stale
      vi.advanceTimersByTime(150);
      
      // Add new entry that exceeds watermark, should trigger cleanup
      watermarkCache.set('new', new Uint8Array(10));
      
      expect(watermarkCache.get('expire1')).toBeUndefined();
      expect(watermarkCache.get('expire2')).toBeUndefined();
      expect(watermarkCache.get('new')).toBeDefined();
    });
  });
});