// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
import { describe, it, expect } from "vitest";
import { SecureLRUCache } from "../../src/secure-cache";
import { resolveSecureLRUOptions } from "../../src/config";

const BYTES = new Uint8Array(32).fill(1);

describe("Experimental SIEVE profile basic behavior", () => {
  it("set/get/delete works and eviction occurs at capacity", () => {
    const opts = resolveSecureLRUOptions("experimental-sieve");
    const cache = new SecureLRUCache<string, Uint8Array>({
      maxEntries: 4,
      maxBytes: 64 * 1024,
      ...(opts as any),
    });
    cache.set("A", BYTES);
    cache.set("B", BYTES);
    cache.set("C", BYTES);
    cache.set("D", BYTES);
    // Reference a couple keys to set second-chance bits
    expect(cache.get("B")).toBeTruthy();
    expect(cache.get("D")).toBeTruthy();
    // Insert one more to force eviction
    cache.set("E", BYTES);
    const stats = cache.getStats();
    expect(stats.evictions).toBeGreaterThanOrEqual(1);
    // Deletion should work
    cache.delete("E");
    expect(cache.get("E")).toBeUndefined();
  });
});
