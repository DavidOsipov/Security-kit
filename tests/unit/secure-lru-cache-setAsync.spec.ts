// SPDX-License-Identifier: MIT
import { describe, it, expect } from "vitest";
import { SecureLRUCache } from "../../src/secure-cache";

describe("SecureLRUCache.setAsync cooperative eviction", () => {
  it("succeeds where sync set would exceed eviction budget", async () => {
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 3,
      maxBytes: 300,
      maxEntryBytes: 200,
      maxSyncEvictions: 1, // very small sync budget to force async path
      ttlAutopurge: false,
      copyOnSet: false,
      copyOnGet: false,
    });

    // Fill cache with three 90-byte entries (approx)
    const make = (n: number) => new Uint8Array(90).fill(n);
    cache.set("a", make(1));
    cache.set("b", make(2));
    cache.set("c", make(3));

    // Next insert of 150 bytes requires evicting at least one (maybe two) entries.
    const big = new Uint8Array(150).fill(9);

    // Sync set may throw because it can only evict 1 entry with budget=1
    let syncErrored = false;
    try {
      cache.set("d", big);
    } catch {
      syncErrored = true;
    }
    expect(syncErrored).toBe(true);

    // Async set should cooperatively evict across microtasks and succeed
    await cache.setAsync("d", big);
    expect(cache.get("d")?.length).toBe(150);

    const stats = cache.getStats();
    expect(stats.size).toBeLessThanOrEqual(3);
    expect(stats.totalBytes).toBeLessThanOrEqual(300);
  });
});
