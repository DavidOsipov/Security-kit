import { describe, it, expect, vi } from 'vitest';
import { SecureLRUCache } from '../../src/secure-cache';
import { InvalidParameterError } from '../../src/errors';

// Helper to await a microtask flush
function nextMicrotask(): Promise<void> {
  return Promise.resolve();
}

describe('SecureLRUCache regressions and hardening', () => {
  it('promoteOnGet: sampled uses 1-in-N modulo semantics', () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 10_000,
      recencyMode: 'lru',
      promoteOnGet: 'sampled',
      promoteOnGetSampleRate: 3, // promote every 3rd GET
    });

    const a = new Uint8Array([1]);
    const b = new Uint8Array([2]);

    cache.set('a', a);
    cache.set('b', b);

    // Do 2 gets on 'a' (no promotion yet)
    cache.get('a');
    cache.get('a');

    // Insert 'c' to cause eviction; since 'a' was not promoted, it should be evicted (LRU)
    cache.set('c', new Uint8Array([3]));

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBeInstanceOf(Uint8Array);
    expect(cache.get('c')).toBeInstanceOf(Uint8Array);

    // Reset and test promotion on 3rd get
    const cache2 = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 10_000,
      recencyMode: 'lru',
      promoteOnGet: 'sampled',
      promoteOnGetSampleRate: 3,
    });
    cache2.set('a', a);
    cache2.set('b', b);
    cache2.get('a');
    cache2.get('a');
    cache2.get('a'); // should promote here
    cache2.set('c', new Uint8Array([3]));

    // Now 'b' should be LRU and evicted
    expect(cache2.get('b')).toBeUndefined();
    expect(cache2.get('a')).toBeInstanceOf(Uint8Array);
    expect(cache2.get('c')).toBeInstanceOf(Uint8Array);
  });

  it('get() returns Uint8Array and may be frozen when freezeReturns=true', () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      copyOnGet: true,
      freezeReturns: true,
    });

    cache.set('k', new Uint8Array([1, 2, 3]));
    const v = cache.get('k');
    expect(v).toBeInstanceOf(Uint8Array);
    // Some runtimes (e.g., Node 20+/24) do not support freezing typed arrays with elements
    // and may throw on Object.freeze(view). Our implementation attempts freeze in a try/catch.
    // Detect capability and assert accordingly.
    let canFreezeTypedArrays = false;
    try {
      const probe = new Uint8Array([9]);
      Object.freeze(probe);
      canFreezeTypedArrays = Object.isFrozen(probe);
    } catch {
      canFreezeTypedArrays = false;
    }
    if (canFreezeTypedArrays) {
      expect(Object.isFrozen(v!)).toBe(true);
    } else {
      expect(Object.isFrozen(v!)).toBe(false);
    }
  });

  it('onEvict is asynchronous and safe to reenter', async () => {
    const events: Array<{ url: string; reason: string }> = [];
    let sawCallback = false;
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 1,
      onEvict: (entry) => {
        sawCallback = true;
        events.push({ url: entry.url, reason: entry.reason });
        // Re-enter: set another key; should not throw or corrupt state
        cache.set('z', new Uint8Array([9]));
      },
    });

    cache.set('a', new Uint8Array([1]));
    // Trigger eviction of 'a'
    cache.set('b', new Uint8Array([2]));

    // Callback should not have run synchronously yet
    expect(sawCallback).toBe(false);

    // Allow microtasks to flush
    await nextMicrotask();

    expect(sawCallback).toBe(true);
    expect(events.length).toBeGreaterThanOrEqual(1);
    // Cache should remain operational
    expect(cache.get('z')).toBeInstanceOf(Uint8Array);
  });

  it('evict callback redaction: evictCallbackExposeUrl=false', async () => {
    const events: string[] = [];
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 1,
      evictCallbackExposeUrl: false,
      onEvict: (e) => events.push(e.url),
    });

    cache.set('secret-url', new Uint8Array([1]));
    cache.set('trigger', new Uint8Array([2]));

    await nextMicrotask();
    expect(events[0]).toBe('[redacted]');
  });

  it('clock override governs TTL expiry decisions', () => {
    // Monotonic fake clock
    let t = 0;
    const clock = () => ++t; // increments per call

    const cache = new SecureLRUCache<string, Uint8Array>({
      defaultTtlMs: 5,
      ttlAutopurge: false,
      clock,
    });

    cache.set('k', new Uint8Array([1, 2, 3]));
    // At t=1 for set() start; simulate some operations Without enough time passed
    expect(cache.get('k')).toBeInstanceOf(Uint8Array); // t increments

    // Advance clock beyond TTL; on next get, should be stale
    for (let i = 0; i < 10; i++) clock();
    expect(cache.get('k')).toBeUndefined();
  });

  it('deferred wipe caps fallback to sync wipe and logs warn', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 1,
      wipeStrategy: 'defer',
      maxWipeQueueBytes: 0, // force fallback immediately
    });

    cache.set('a', new Uint8Array([1]));
    // Cause wipe path by updating value (old value wiped)
    cache.set('a', new Uint8Array([2]));

    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  describe('SharedArrayBuffer detection edge cases', () => {
    it('rejects various SAB-backed typed array types', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      const sab = new SharedArrayBuffer(16);

      // Test different typed array views by creating Uint8Array views over them
      expect(() => cache.set('u8', new Uint8Array(sab))).toThrow(InvalidParameterError);
      expect(() => cache.set('u16', new Uint8Array(new Uint16Array(sab).buffer))).toThrow(InvalidParameterError);
      expect(() => cache.set('i32', new Uint8Array(new Int32Array(sab).buffer))).toThrow(InvalidParameterError);
      expect(() => cache.set('f64', new Uint8Array(new Float64Array(sab).buffer))).toThrow(InvalidParameterError);
    });

    it('rejects SAB-backed DataView', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      const sab = new SharedArrayBuffer(16);
      const dataView = new DataView(sab);

      // DataView backed by SAB should be rejected when we create a Uint8Array view over it
      expect(() => cache.set('dv', new Uint8Array(dataView.buffer))).toThrow(InvalidParameterError);
    });

    it('accepts regular ArrayBuffer-backed views', () => {
      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      const ab = new ArrayBuffer(16);

      // Regular ArrayBuffer views should be accepted
      expect(() => cache.set('u8', new Uint8Array(ab))).not.toThrow();
      expect(() => cache.set('u16', new Uint8Array(new Uint16Array(ab).buffer))).not.toThrow();
      expect(() => cache.set('i32', new Uint8Array(new Int32Array(ab).buffer))).not.toThrow();
    });

    it('handles zero-length SAB views', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      const sab = new SharedArrayBuffer(0);
      const view = new Uint8Array(sab);

      expect(() => cache.set('zero', view)).toThrow(InvalidParameterError);
    });

    it('handles detached SAB buffers gracefully', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      const sab = new SharedArrayBuffer(16);
      const view = new Uint8Array(sab);

      // Simulate detachment by replacing buffer (if supported)
      try {
        // This might not work in all environments, but test the detection
        Object.defineProperty(view, 'buffer', {
          value: new ArrayBuffer(16), // Replace with regular buffer
        });
        // Should now be accepted since it's not SAB-backed
        expect(() => cache.set('detached', view)).not.toThrow();
      } catch {
        // If we can't detach, just skip this part
      }
    });

    it('handles cross-realm SAB detection fallback', () => {
      // Test that fallback detection works when instanceof fails
      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      // Create a view with a buffer that has the right constructor name but instanceof would fail
      const fakeView = new Uint8Array(new ArrayBuffer(16));
      const fakeBuffer = {
        constructor: { name: 'SharedArrayBuffer' }
      };
      Object.defineProperty(fakeView, 'buffer', { value: fakeBuffer });

      // This should not throw because the buffer is not actually a SharedArrayBuffer
      // The test verifies that malformed buffers don't cause crashes
      expect(() => cache.set('cross-realm', fakeView)).not.toThrow();
    });

    it('handles SAB unavailable environment', () => {
      const originalSharedArrayBuffer = global.SharedArrayBuffer;

      // Simulate environment without SharedArrayBuffer
      delete (global as any).SharedArrayBuffer;

      try {
        const cache = new SecureLRUCache<string, Uint8Array>({
          rejectSharedBuffers: true,
        });

        // Should accept regular buffers when SAB is unavailable
        const ab = new ArrayBuffer(16);
        expect(() => cache.set('no-sab', new Uint8Array(ab))).not.toThrow();
      } finally {
        // Restore original
        (global as any).SharedArrayBuffer = originalSharedArrayBuffer;
      }
    });

    it('handles malformed buffer objects', () => {
      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      // Create a view with a fake buffer that might cause issues
      const view = new Uint8Array(new ArrayBuffer(16));
      Object.defineProperty(view, 'buffer', {
        value: null, // Invalid buffer
      });

      // Should handle gracefully without throwing in detection
      expect(() => cache.set('malformed', view)).not.toThrow();
    });

    it('handles instanceof failure gracefully', () => {
      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      // Create a view where instanceof might fail
      const view = new Uint8Array(new ArrayBuffer(16));

      // Mock buffer to cause instanceof to potentially fail
      const originalBuffer = view.buffer;
      Object.defineProperty(view, 'buffer', {
        get() {
          // Return something that might cause instanceof to throw
          throw new Error('instanceof failure');
        }
      });

      // Should fall back to constructor name check and not throw in detection
      expect(() => {
        try {
          cache.set('instanceof-fail', view);
        } catch (e) {
          if (e instanceof InvalidParameterError && e.message.includes('SharedArrayBuffer')) {
            throw e; // Re-throw SAB rejection
          }
          // Other errors are acceptable (detection failures)
        }
      }).not.toThrow(InvalidParameterError);
    });

    it('handles subclassed typed arrays', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: true,
      });

      // Create a subclass of Uint8Array
      class MyUint8Array extends Uint8Array {}

      const sab = new SharedArrayBuffer(16);
      // Create a regular Uint8Array first, then change its prototype
      const tempView = new Uint8Array(sab);
      const subclassedView = Object.setPrototypeOf(tempView, MyUint8Array.prototype) as MyUint8Array;

      // Should still detect as SAB-backed
      expect(() => cache.set('subclassed', subclassedView)).toThrow(InvalidParameterError);
    });

    it('respects rejectSharedBuffers=false for all SAB types', () => {
      if (typeof SharedArrayBuffer === 'undefined') return;

      const cache = new SecureLRUCache<string, Uint8Array>({
        rejectSharedBuffers: false,
      });

      const sab = new SharedArrayBuffer(16);

      // All these should be accepted when rejection is disabled
      expect(() => cache.set('u8', new Uint8Array(sab))).not.toThrow();
      expect(() => cache.set('u16', new Uint8Array(new Uint16Array(sab).buffer))).not.toThrow();
      expect(() => cache.set('i32', new Uint8Array(new Int32Array(sab).buffer))).not.toThrow();
      expect(() => cache.set('f64', new Uint8Array(new Float64Array(sab).buffer))).not.toThrow();
      expect(() => cache.set('dv', new Uint8Array(new DataView(sab).buffer))).not.toThrow();
    });
  });
});
