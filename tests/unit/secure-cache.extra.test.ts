import { describe, it, expect } from "vitest";
import { SecureLRUCache } from "../../src/secure-cache";

describe("SecureLRUCache additional edge tests", () => {
  it("large wipe triggers synchronous fallback when caps too small", () => {
    const warnings: string[] = [];
    const logger = {
      warn: (...data: readonly unknown[]) => warnings.push(String(data[0] ?? "")),
      error: (_: readonly unknown[]) => {},
    };

    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 2,
      maxBytes: 1024,
      wipeStrategy: "defer",
      maxWipeQueueBytes: 1, // force immediate sync fallback for any multi-byte buffer
      maxWipeQueueEntries: 1,
      logger,
      // ensure onEvictDispatch sync to avoid microtask timing surprises
      onEvictDispatch: "sync",
    });

    cache.set("x", new Uint8Array([1, 2, 3]));
    // Deleting should attempt deferred wipe but fall back to sync due to tiny caps
    cache.delete("x");

    // The implementation coalesces warnings; but on first fallback it should log immediate warn
    expect(warnings.some((s) => s.includes("Deferred wipe caps exceeded"))).toBe(true);
  });

  it("SIEVE eviction prefers unreferenced entries", () => {
    const evicted: string[] = [];
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 3,
      maxBytes: 1024,
      recencyMode: "sieve",
      onEvict: (e) => evicted.push(e.url as string),
      evictCallbackExposeUrl: true,
      onEvictDispatch: "sync",
    });

    cache.set("a", new Uint8Array([1]));
    cache.set("b", new Uint8Array([2]));
    cache.set("c", new Uint8Array([3]));

    // Mark 'a' and 'b' as referenced, leaving 'c' unreferenced
    expect(cache.get("a")).toBeDefined();
    expect(cache.get("b")).toBeDefined();

    // Insert a new entry to force eviction
    cache.set("d", new Uint8Array([4]));

    // Since onEvictDispatch is sync, we should have at least one evicted entry and it should be 'c'
    expect(evicted.length).toBeGreaterThanOrEqual(1);
    expect(evicted[0]).toBe("c");
  });

  it("flushWipes drains deferred wipe queue", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 10,
      maxBytes: 1024 * 10,
      wipeStrategy: "defer",
      maxDeferredWipesPerFlush: 2,
      maxWipeQueueBytes: 1024 * 10,
    });

    // enqueue several wipes
    for (let i = 0; i < 5; i++) {
      cache.set(String(i), new Uint8Array([i + 1]));
    }

    for (let i = 0; i < 5; i++) {
      cache.delete(String(i));
    }

    // Wait a tick for microtask scheduling then flush
    await Promise.resolve();
    await cache.flushWipes();
    const stats = cache.getWipeQueueStats();
    expect(stats.entries).toBe(0);
  });
});
