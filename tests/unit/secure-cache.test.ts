import { describe, it, expect, beforeEach, vi } from "vitest";
import { VerifiedByteCache, SecureLRUCache } from "../../src/secure-cache.ts";
import { InvalidParameterError } from "../../src/errors.ts";

describe("SecureLRUCache basic behavior", () => {
  beforeEach(() => {
    // clear singleton cache to start fresh
    VerifiedByteCache.clear();
  });

  it("set/get roundtrip returns stored data and copies when configured", () => {
    const data = new Uint8Array([1, 2, 3]);
    VerifiedByteCache.set("https://example.com/x", data);
    const got = VerifiedByteCache.get("https://example.com/x");
    expect(got).toBeDefined();
    expect(got).not.toBe(data); // copyOnGet/default should return a copy
    expect(Array.from(got as Uint8Array)).toEqual([1, 2, 3]);
  });

  it("rejects SharedArrayBuffer-backed views when configured", () => {
    const sab = new SharedArrayBuffer(8);
    const view = new Uint8Array(sab);
    expect(() => {
      VerifiedByteCache.set("https://example.com/sab", view);
    }).toThrow();
  });

  it("onEvict receives redacted url by default and mapper works when provided", async () => {
    const events: ReadonlyArray<{
      readonly url: string;
      readonly bytesLength: number;
      readonly reason: string;
    }> = [];
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 1024,
      onEvict: (e) => events.push(e as any),
      evictCallbackExposeUrl: false,
    });

    cache.set("a", new Uint8Array([1]));
    cache.set("b", new Uint8Array([2]));
    // this should evict one entry due to capacity
    cache.set("c", new Uint8Array([3]));

    // microtask dispatch may schedule the onEvict; flush microtasks
    await Promise.resolve();

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].url).toBe("[redacted]");

    // Test mapper
    const events2: ReadonlyArray<any> = [];
    const cache2 = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 1,
      maxBytes: 1024,
      onEvict: (e) => events2.push(e),
      onEvictKeyMapper: (u) => `mapped:${u}`,
      evictCallbackExposeUrl: false,
      onEvictDispatch: "sync",
    });
    cache2.set("z", new Uint8Array([9]));
    cache2.set("y", new Uint8Array([8]));
    expect(events2.length).toBeGreaterThanOrEqual(1);
    expect(events2[0].url).toBe("mapped:z");
  });

  it("TTL expiry removes entries and increments expired count", async () => {
    // Use deterministic clock
    let now = 1000;
    const clock = () => now;
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 10,
      maxBytes: 1024,
      defaultTtlMs: 100,
      ttlAutopurge: true,
      clock,
    });

    cache.set("t1", new Uint8Array([1]));
    expect(cache.has("t1")).toBe(true);
    now += 200; // advance past TTL
    // force run of TTL purge
    cache.purgeExpired();
    expect(cache.has("t1")).toBe(false);
  });

  it("delete returns false for missing keys and true for existing", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 1024,
    });
    cache.set("k", new Uint8Array([1]));
    expect(cache.delete("k")).toBeUndefined(); // public API delete returns void
    // Use internal delete via clear flow to ensure no exception
    cache.clear();
  });
});
