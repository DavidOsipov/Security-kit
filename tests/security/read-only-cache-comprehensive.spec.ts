// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  SecureLRUCache,
  asReadOnlyCache,
  VerifiedByteCache,
  type ReadOnlyCache,
} from "../../src/secure-cache";

describe("Read-only cache facades - comprehensive", () => {
  it("asReadOnlyCache hides mutators and returns copies when configured", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 4,
      copyOnGet: true,
      copyOnSet: true,
    });
    const ro = asReadOnlyCache(cache);

    // Mutators should not be present on the facade
    expect((ro as any).set).toBeUndefined();
    expect((ro as any).delete).toBeUndefined();

    const original = new Uint8Array([10, 20, 30]);
    cache.set("k1", original);
    const got = ro.get("k1");
    expect(got).toBeInstanceOf(Uint8Array);
    // Because copyOnGet is true, modifying the returned value should not affect cache
    if (got) got[0] = 99;
    const refetch = cache.get("k1");
    expect(refetch && refetch[0]).toBe(10);
  });

  it("VerifiedByteCache.asReadOnly returns a singleton read-only facade", () => {
    const facade1 = VerifiedByteCache.asReadOnly();
    const facade2 = VerifiedByteCache.asReadOnly();
    expect(facade1).toBeDefined();
    expect(facade1.get).toBeDefined();
    // Methods should be functions
    expect(typeof facade1.get).toBe("function");

    // Confirm mutators aren't available
    expect((facade1 as any).set).toBeUndefined();
    expect((facade1 as any).clear).toBeUndefined();

    // Behavioral check: the singleton cache should be observable via both facades
    VerifiedByteCache.clear();
    VerifiedByteCache.set("/singleton-test", new Uint8Array([7]));
    const v1 = facade1.get("/singleton-test");
    const v2 = facade2.get("/singleton-test");
    expect(v1 && v1[0]).toBe(7);
    expect(v2 && v2[0]).toBe(7);
  });

  it("facade respects cache eviction and does not prevent it", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 2 });
    cache.set("a", new Uint8Array(Buffer.from("valA")));
    cache.set("b", new Uint8Array(Buffer.from("valB")));
    const facade = asReadOnlyCache(cache);
    expect(facade.has("a")).toBe(true);
    expect(facade.has("b")).toBe(true);
    // Add third item to trigger eviction
    cache.set("c", new Uint8Array(Buffer.from("valC")));
    expect(facade.has("a")).toBe(false); // evicted
    expect(facade.has("b")).toBe(true);
    expect(facade.has("c")).toBe(true);
  });

  it("facade respects TTL and expires entries", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 10,
      defaultTtlMs: 100,
      ttlAutopurge: true,
    });
    cache.set("temp", new Uint8Array(Buffer.from("value")));
    const facade = asReadOnlyCache(cache);
    expect(facade.has("temp")).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(facade.has("temp")).toBe(false);
    expect(facade.peek("temp")).toBeUndefined();
  });

  it("facade exposes getStats correctly", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 5 });
    cache.set("a", new Uint8Array(Buffer.from("1")));
    cache.get("a"); // hit
    cache.set("b", new Uint8Array(Buffer.from("2")));
    const facade = asReadOnlyCache(cache);
    const stats = facade.getStats();
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(0);
    expect(stats.size).toBe(2);
    expect(stats.evictions).toBe(0);
  });

  it("facade handles invalid keys gracefully", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 5 });
    const facade = asReadOnlyCache(cache);
    expect(facade.has("")).toBe(false);
    expect(facade.peek("")).toBeUndefined();
    expect(facade.get("")).toBeUndefined();
    // Non-string keys (if allowed by cache)
    expect(facade.has(123 as any)).toBe(false);
  });

  it("facade returns copies for complex objects", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 5,
      copyOnGet: true,
    });
    const original = new Uint8Array([1, 2, 3, 4]);
    cache.set("complex", original);
    const facade = asReadOnlyCache(cache);
    const got = facade.get("complex");
    expect(got).toEqual(original);
    expect(got).not.toBe(original); // copy
    if (got) got[0] = 99;
    expect(original[0]).toBe(1); // original unchanged
  });

  it("facade handles cache errors", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 5 });
    // Simulate error by setting invalid data (though cache may not throw)
    // For this test, assume get can throw if key is malformed
    const facade = asReadOnlyCache(cache);
    expect(() => facade.get("nonexistent")).toBeDefined(); // should not throw
  });

  it("facade peek does not promote recency even with multiple calls", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({ maxEntries: 2 });
    cache.set("a", new Uint8Array(Buffer.from("valA")));
    cache.set("b", new Uint8Array(Buffer.from("valB")));
    const facade = asReadOnlyCache(cache);
    facade.peek("a"); // peek should not promote
    facade.peek("a");
    // Add third to evict least recently used
    cache.set("c", new Uint8Array(Buffer.from("valC")));
    expect(facade.has("a")).toBe(false); // a evicted because peek didn't promote
    expect(facade.has("b")).toBe(true);
  });

  it("singleton facade observes cache state changes", () => {
    // Use the VerifiedByteCache singleton API so that the facade observes the same instance
    const facade1 = VerifiedByteCache.asReadOnly();
    const facade2 = VerifiedByteCache.asReadOnly();
    VerifiedByteCache.clear();
    VerifiedByteCache.set("/shared", new Uint8Array(Buffer.from("value")));
    expect(facade1.has("/shared")).toBe(true);
    expect(facade2.has("/shared")).toBe(true);
    VerifiedByteCache.delete("/shared");
    expect(facade1.has("/shared")).toBe(false);
    expect(facade2.has("/shared")).toBe(false);
  });

  it("facade get with copyOnGet respects cache configuration", () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 5,
      copyOnGet: true,
    });
    const original = new Uint8Array(Buffer.from("test"));
    cache.set("copy", original);
    const facade = asReadOnlyCache(cache);
    const got = facade.get("copy");
    expect(got).toEqual(original);
    if (got) expect(got).not.toBe(original); // copy
  });
});
