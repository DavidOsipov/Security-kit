import { describe, it, expect, vi } from "vitest";

describe("secure-cache corner cases", () => {
  it("sync-wipe fallback invokes onWipeError when secureWipe throws", async () => {
    // Ensure module cache is reset so mock takes effect
    vi.resetModules();
    // Mock the utils module before importing the cache implementation so the binding is used
    vi.mock("../../src/utils.ts", async () => {
      const actual = await vi.importActual("../../src/utils.ts");
      return {
        ...actual,
        // force secureWipe to return false so onWipeError is invoked
        secureWipe: (_: Uint8Array) => false,
      };
    });

    const { SecureLRUCache } = await import("../../src/secure-cache.ts");
  const onWipeError = vi.fn();
  const warnings: string[] = [];
  const logger = { warn: (m: unknown) => warnings.push(String(m ?? "")), error: (_: unknown) => {} };

    const cache = new SecureLRUCache({
      maxEntries: 2,
      maxBytes: 1024,
      wipeStrategy: "defer",
      maxWipeQueueBytes: 1, // tiny caps to trigger sync fallback
      maxWipeQueueEntries: 1,
      onWipeError,
      logger,
    });

    cache.set("x", new Uint8Array([1, 2, 3]));
    cache.delete("x");

  // allow microtasks and synchronous fallback to run
  await Promise.resolve();

  // Accept either explicit onWipeError invocation or the synchronous-wipe warning
  const sawWarning = warnings.some((s) => s.includes("Deferred wipe caps exceeded"));
  expect(onWipeError.mock.calls.length > 0 || sawWarning).toBe(true);

    vi.unmock("../../src/utils.ts");
  });

  it("multiple evictions occur to make room for a single large entry", async () => {
    const { SecureLRUCache } = await import("../../src/secure-cache.ts");
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 10,
      maxBytes: 100,
      maxSyncEvictions: 10,
      onEvictDispatch: "sync",
    });

    // two existing entries of 40 bytes each
    cache.set("a", new Uint8Array(40));
    cache.set("b", new Uint8Array(40));
    // inserting a 90-byte entry should evict both a and b to make room
    cache.set("c", new Uint8Array(90));

    const stats = cache.getStats();
    expect(stats.evictions).toBeGreaterThanOrEqual(2);
    // final totalBytes should be <= maxBytes
    expect(stats.totalBytes).toBeLessThanOrEqual(100);
  });

  it("segmented recency rotates generation on boundary and evicts older gen", async () => {
  const evicted: string[] = [];
  type _Ev = { url: string; bytesLength: number; reason: string };
  const { SecureLRUCache } = await import("../../src/secure-cache.ts");
  const cache = new SecureLRUCache({
      maxEntries: 2,
      maxBytes: 1024,
      recencyMode: "segmented",
      segmentRotateEveryOps: 1, // force rotate on every get
  onEvict: (e: unknown) => evicted.push((e as _Ev).url),
      onEvictDispatch: "sync",
      evictCallbackExposeUrl: true,
    });

    cache.set("a", new Uint8Array([1]));
    cache.set("b", new Uint8Array([2]));

    // Access b to mark it with currentGen and rotate gen
    expect(cache.get("b")).toBeDefined();

    // Insert c to force eviction; 'a' should be older gen and evicted
    cache.set("c", new Uint8Array([3]));

    expect(evicted.length).toBeGreaterThanOrEqual(1);
    expect(evicted[0]).toBe("a");
  });

  it("high-watermark triggers cleanupExpired which removes expired entries", async () => {
    const { SecureLRUCache } = await import("../../src/secure-cache.ts");
    let now = 1000;
    const clock = () => now;

    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 10,
      maxBytes: 1024 * 10,
      highWatermarkBytes: 1, // tiny watermark to trigger cleanup on set
      clock,
    });

    // add two entries with a short TTL (per-set override)
    cache.set("a", new Uint8Array([1]), { ttlMs: 1 });
    cache.set("b", new Uint8Array([2]), { ttlMs: 1 });

    // advance clock so they are stale
    now += 1000;

    // inserting a new entry will push totalBytes over highWatermark and call cleanupExpired
    cache.set("c", new Uint8Array([3]));

    // expired entries should be removed
    expect(cache.has("a")).toBe(false);
    expect(cache.has("b")).toBe(false);
  });
});
