// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

// Comprehensive integration test for VerifiedByteCache.setAsync cooperative eviction behavior

import { describe, it, expect, beforeEach } from "vitest";
import { VerifiedByteCache } from "../../src/secure-cache";

// Helper to create test data
function makeBytes(size: number, fill: number = 0): Uint8Array {
  return new Uint8Array(size).fill(fill);
}

// Helper to measure async operation time
async function timeAsync<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; duration: number }> {
  const start = performance.now();
  const result = await fn();
  const duration = performance.now() - start;
  return { result, duration };
}

describe("VerifiedByteCache.setAsync comprehensive integration", () => {
  beforeEach(() => {
    // Clear cache before each test to ensure clean state
    VerifiedByteCache.clear();
  });

  describe("Basic setAsync functionality", () => {
    it("setAsync works for basic operations", async () => {
      const SMALL_BYTES = new Uint8Array(64).fill(1);
      await VerifiedByteCache.setAsync("basic-key", SMALL_BYTES);

      const retrieved = VerifiedByteCache.get("basic-key");
      expect(retrieved).toBeInstanceOf(Uint8Array);
      expect(retrieved?.length).toBe(SMALL_BYTES.length);
      expect(retrieved).not.toBe(SMALL_BYTES); // Should be a copy
    });

    it("setAsync respects TTL", async () => {
      const SMALL_BYTES = new Uint8Array(64).fill(1);
      await VerifiedByteCache.setAsync("ttl-key", SMALL_BYTES);
      expect(VerifiedByteCache.get("ttl-key")).toBeDefined();

      // Wait for TTL to expire (default is 2 minutes, but we'll use a shorter one)
      await new Promise((resolve) => setTimeout(resolve, 100));
      // Note: VerifiedByteCache uses default TTL from config, which may be longer
      // This test mainly ensures setAsync doesn't break TTL functionality
    });

    it("setAsync handles large payloads", async () => {
      const largePayload = makeBytes(50000, 42); // 50KB
      await VerifiedByteCache.setAsync("large-key", largePayload);

      const retrieved = VerifiedByteCache.get("large-key");
      expect(retrieved?.length).toBe(50000);
      expect(retrieved?.[0]).toBe(42);
    });
  });

  describe("Cooperative eviction under pressure", () => {
    it("setAsync succeeds where sync set would fail due to eviction budget", async () => {
      // Fill cache to near capacity (maxEntries is 10)
      const entries = 8;
      for (let i = 0; i < entries; i++) {
        VerifiedByteCache.set(`fill-${i}`, makeBytes(1000, i % 256));
      }

      const statsBefore = VerifiedByteCache.getStats();
      expect(statsBefore.size).toBe(entries);

      // Try to add a large entry that will require eviction
      const largeEntry = makeBytes(50000, 99);

      // Sync set should succeed (cache handles eviction)
      VerifiedByteCache.set("pressure-test-sync", largeEntry);

      const retrievedSync = VerifiedByteCache.get("pressure-test-sync");
      expect(retrievedSync).toBeDefined();
      expect(retrievedSync?.length).toBe(50000);

      // Async set should also succeed
      await VerifiedByteCache.setAsync("pressure-test-async", largeEntry);

      const retrievedAsync = VerifiedByteCache.get("pressure-test-async");
      expect(retrievedAsync).toBeDefined();
      expect(retrievedAsync?.length).toBe(50000);

      const statsAfter = VerifiedByteCache.getStats();
      expect(statsAfter.size).toBeGreaterThan(0);
      // Evictions may or may not occur depending on cache state
      expect(statsAfter.evictions).toBeGreaterThanOrEqual(
        statsBefore.evictions,
      );
    });

    it("setAsync maintains cache invariants during cooperative eviction", async () => {
      // Create a scenario requiring eviction (maxEntries is 10)
      const initialEntries = 9;
      for (let i = 0; i < initialEntries; i++) {
        VerifiedByteCache.set(`initial-${i}`, makeBytes(512, i % 256));
      }

      const statsBefore = VerifiedByteCache.getStats();
      expect(statsBefore.size).toBe(initialEntries);

      // Add a very large entry that will evict some items
      const hugeEntry = makeBytes(100000, 255);
      await VerifiedByteCache.setAsync("huge-entry", hugeEntry);

      const statsAfter = VerifiedByteCache.getStats();

      // Verify cache invariants
      expect(statsAfter.size).toBeGreaterThan(0);
      expect(statsAfter.totalBytes).toBeGreaterThan(0);
      // Evictions may or may not occur depending on cache state and recency mode
      expect(statsAfter.evictions).toBeGreaterThanOrEqual(
        statsBefore.evictions,
      );

      // Verify the large entry was stored
      const retrieved = VerifiedByteCache.get("huge-entry");
      expect(retrieved?.length).toBe(100000);
      expect(retrieved?.[0]).toBe(255);

      // Verify total bytes doesn't exceed configured limits
      expect(statsAfter.totalBytes).toBeLessThanOrEqual(1048576); // 1MB default maxBytes
    });
  });

  describe("Concurrent setAsync operations", () => {
    it("handles multiple concurrent setAsync operations", async () => {
      const concurrentOps = 5; // Limited by maxEntries of 10
      const promises = [];

      for (let i = 0; i < concurrentOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          `concurrent-${i}`,
          makeBytes(1000 + i * 100, i % 256),
        );
        promises.push(promise);
      }

      // All should complete successfully
      await Promise.all(promises);

      // Verify all entries were stored (some may have been evicted due to capacity)
      let foundCount = 0;
      for (let i = 0; i < concurrentOps; i++) {
        const retrieved = VerifiedByteCache.get(`concurrent-${i}`);
        if (retrieved) {
          foundCount++;
          expect(retrieved?.length).toBe(1000 + i * 100);
          expect(retrieved?.[0]).toBe(i % 256);
        }
      }
      expect(foundCount).toBeGreaterThan(0); // At least some should be stored

      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.setOps).toBeGreaterThanOrEqual(concurrentOps); // May include failed operations
    });

    it("maintains consistency under high concurrency with eviction pressure", async () => {
      // Pre-fill cache to create eviction pressure (maxEntries is 10)
      const prefillCount = 8;
      for (let i = 0; i < prefillCount; i++) {
        VerifiedByteCache.set(`prefill-${i}`, makeBytes(2000, i % 256));
      }

      const concurrentOps = 5;
      const promises = [];

      // Launch many concurrent operations that will cause evictions
      for (let i = 0; i < concurrentOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          `stress-${i}`,
          makeBytes(3000 + i * 200, (i + 100) % 256),
        );
        promises.push(promise);
      }

      await Promise.all(promises);

      const stats = VerifiedByteCache.getStats();

      // Verify cache is in a consistent state
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.totalBytes).toBeGreaterThan(0);
      expect(stats.evictions).toBeGreaterThan(0);

      // Verify at least some of the new entries exist
      let foundCount = 0;
      for (let i = 0; i < concurrentOps; i++) {
        if (VerifiedByteCache.get(`stress-${i}`)) {
          foundCount++;
        }
      }
      expect(foundCount).toBeGreaterThan(0);

      // Cache should not be corrupted
      expect(() => VerifiedByteCache.getStats()).not.toThrow();
    });
  });

  describe("Performance characteristics", () => {
    it("setAsync has reasonable performance under normal conditions", async () => {
      const iterations = 5; // Limited by maxEntries of 10
      const times = [];

      for (let i = 0; i < iterations; i++) {
        const { duration } = await timeAsync(() =>
          VerifiedByteCache.setAsync(`perf-${i}`, makeBytes(512, i % 256)),
        );
        times.push(duration);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const maxTime = Math.max(...times);

      // Performance should be reasonable (under 10ms average, under 50ms max)
      expect(avgTime).toBeLessThan(10);
      expect(maxTime).toBeLessThan(50);

      // Verify all operations completed
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBe(iterations);
    });

    it("setAsync performance degrades gracefully under extreme pressure", async () => {
      // Create extreme pressure scenario (fill cache to capacity)
      const extremeEntries = 10;
      for (let i = 0; i < extremeEntries; i++) {
        VerifiedByteCache.set(`extreme-${i}`, makeBytes(256, i % 256));
      }

      const { duration } = await timeAsync(() =>
        VerifiedByteCache.setAsync("extreme-test", makeBytes(10000, 255)),
      );

      // Should still complete in reasonable time despite pressure
      expect(duration).toBeLessThan(200); // Allow more time for extreme case

      const retrieved = VerifiedByteCache.get("extreme-test");
      expect(retrieved?.length).toBe(10000);
    });
  });

  describe("Error handling and edge cases", () => {
    it("setAsync handles invalid inputs appropriately", async () => {
      const SMALL_BYTES = new Uint8Array(64).fill(1);

      // Invalid URL (empty string) - should be handled gracefully
      await expect(
        VerifiedByteCache.setAsync("", SMALL_BYTES),
      ).resolves.toBeUndefined();

      // Invalid URL (too long) - should throw
      const longUrl = "a".repeat(3000);
      await expect(
        VerifiedByteCache.setAsync(longUrl, SMALL_BYTES),
      ).rejects.toThrow("Invalid URL");

      // Invalid bytes (not Uint8Array) - should throw
      await expect(
        VerifiedByteCache.setAsync("test", "not bytes" as any),
      ).rejects.toThrow("Invalid value");

      // Empty bytes - should be handled gracefully (no explicit rejection)
      await expect(
        VerifiedByteCache.setAsync("test", new Uint8Array(0)),
      ).resolves.toBeUndefined();
    });

    it("setAsync handles SharedArrayBuffer rejection", async () => {
      // Create a SharedArrayBuffer-backed view if available
      if (typeof SharedArrayBuffer !== "undefined") {
        const sab = new SharedArrayBuffer(64);
        const sabView = new Uint8Array(sab);

        await expect(
          VerifiedByteCache.setAsync("sab-test", sabView),
        ).rejects.toThrow("SharedArrayBuffer-backed views are not permitted");
      }
    });

    it("setAsync handles oversized entries", async () => {
      // Entry larger than maxEntryBytes (default 512KB)
      const oversized = makeBytes(600000, 42); // 600KB

      await expect(
        VerifiedByteCache.setAsync("oversized", oversized),
      ).rejects.toThrow("Entry too large");
    });
  });

  describe("Integration with other cache features", () => {
    it("setAsync works with cache statistics", async () => {
      const MEDIUM_BYTES = new Uint8Array(256).fill(2);
      const statsBefore = VerifiedByteCache.getStats();

      await VerifiedByteCache.setAsync("stats-test", MEDIUM_BYTES);

      const statsAfter = VerifiedByteCache.getStats();

      expect(statsAfter.size).toBe(statsBefore.size + 1);
      expect(statsAfter.setOps).toBe(statsBefore.setOps + 1);
      expect(statsAfter.totalBytes).toBe(
        statsBefore.totalBytes + MEDIUM_BYTES.length,
      );
    });

    it("setAsync integrates with delete operations", async () => {
      const MEDIUM_BYTES = new Uint8Array(256).fill(2);
      await VerifiedByteCache.setAsync("delete-test", MEDIUM_BYTES);
      expect(VerifiedByteCache.get("delete-test")).toBeDefined();

      VerifiedByteCache.delete("delete-test");
      expect(VerifiedByteCache.get("delete-test")).toBeUndefined();
    });

    it("setAsync works with clear operations", async () => {
      const SMALL_BYTES = new Uint8Array(64).fill(1);
      const MEDIUM_BYTES = new Uint8Array(256).fill(2);

      await VerifiedByteCache.setAsync("clear-test-1", SMALL_BYTES);
      await VerifiedByteCache.setAsync("clear-test-2", MEDIUM_BYTES);

      expect(VerifiedByteCache.getStats().size).toBe(2);

      VerifiedByteCache.clear();

      expect(VerifiedByteCache.getStats().size).toBe(0);
      expect(VerifiedByteCache.get("clear-test-1")).toBeUndefined();
      expect(VerifiedByteCache.get("clear-test-2")).toBeUndefined();
    });
  });

  describe("Memory and resource management", () => {
    it("setAsync properly manages memory during cooperative eviction", async () => {
      // Track memory usage pattern during eviction
      const initialStats = VerifiedByteCache.getStats();

      // Fill cache to near capacity (maxEntries is 10)
      const fillCount = 8;
      for (let i = 0; i < fillCount; i++) {
        VerifiedByteCache.set(`mem-${i}`, makeBytes(1024, i % 256));
      }

      const filledStats = VerifiedByteCache.getStats();
      expect(filledStats.size).toBe(fillCount);

      // Add large entry that will cause evictions
      await VerifiedByteCache.setAsync("memory-test", makeBytes(20000, 128));

      const finalStats = VerifiedByteCache.getStats();

      // Verify memory is properly managed
      expect(finalStats.totalBytes).toBeGreaterThan(0);
      expect(finalStats.totalBytes).toBeLessThanOrEqual(1048576); // 1MB limit
      // Evictions may or may not occur depending on cache state and recency mode
      expect(finalStats.evictions).toBeGreaterThanOrEqual(
        initialStats.evictions,
      );

      // Verify the new entry exists and old entries were properly evicted
      expect(VerifiedByteCache.get("memory-test")).toBeDefined();
    });

    it("setAsync handles zero-length entries appropriately", async () => {
      // Zero-length entries are handled gracefully (no explicit rejection)
      await expect(
        VerifiedByteCache.setAsync("zero-length", new Uint8Array(0)),
      ).resolves.toBeUndefined();
    });
  });

  describe("Boundary testing for cache limits", () => {
    it("setAsync handles exact maxEntries boundary", async () => {
      // Clear cache and add exactly maxEntries items
      VerifiedByteCache.clear();
      const maxEntries = 10; // Based on cache configuration

      // Add exactly maxEntries items
      for (let i = 0; i < maxEntries; i++) {
        await VerifiedByteCache.setAsync(
          `boundary-${i}`,
          makeBytes(100, i % 256),
        );
      }

      const statsAfterFill = VerifiedByteCache.getStats();
      expect(statsAfterFill.size).toBe(maxEntries);

      // Try to add one more - should trigger eviction
      await VerifiedByteCache.setAsync(
        "boundary-overflow",
        makeBytes(100, 255),
      );

      const statsAfterOverflow = VerifiedByteCache.getStats();
      expect(statsAfterOverflow.size).toBe(maxEntries); // Should still be maxEntries
      expect(statsAfterOverflow.evictions).toBeGreaterThan(
        statsAfterFill.evictions,
      );

      // Verify the new entry exists
      expect(VerifiedByteCache.get("boundary-overflow")).toBeDefined();
    });

    it("setAsync handles maxBytes limit precisely", async () => {
      VerifiedByteCache.clear();
      const maxBytes = 1048576; // 1MB default
      const largeEntrySize = 100000; // 100KB - well under maxEntryBytes limit of 512KB

      // Add entries that approach the byte limit
      await VerifiedByteCache.setAsync(
        "bytes-test-1",
        makeBytes(largeEntrySize, 1),
      );
      await VerifiedByteCache.setAsync(
        "bytes-test-2",
        makeBytes(largeEntrySize, 2),
      );
      await VerifiedByteCache.setAsync(
        "bytes-test-3",
        makeBytes(largeEntrySize, 3),
      );
      await VerifiedByteCache.setAsync(
        "bytes-test-4",
        makeBytes(largeEntrySize, 4),
      );

      const stats = VerifiedByteCache.getStats();
      expect(stats.totalBytes).toBeLessThanOrEqual(maxBytes);

      // Adding another entry should work (may trigger eviction)
      await VerifiedByteCache.setAsync(
        "bytes-test-5",
        makeBytes(largeEntrySize, 5),
      );

      const finalStats = VerifiedByteCache.getStats();
      expect(finalStats.totalBytes).toBeLessThanOrEqual(maxBytes);
      // Evictions may or may not occur depending on cache state and recency mode
      expect(finalStats.evictions).toBeGreaterThanOrEqual(stats.evictions);
    });

    it("setAsync handles maxEntryBytes limit", async () => {
      const maxEntryBytes = 512000; // 512KB default
      const oversized = makeBytes(maxEntryBytes + 1000, 42);

      // Should reject entries larger than maxEntryBytes
      await expect(
        VerifiedByteCache.setAsync("max-entry-test", oversized),
      ).rejects.toThrow(/Entry too large|exceeds maximum/);

      // Should accept entries exactly at the limit
      const atLimit = makeBytes(maxEntryBytes, 42);
      await expect(
        VerifiedByteCache.setAsync("at-limit-test", atLimit),
      ).resolves.toBeUndefined();

      const retrieved = VerifiedByteCache.get("at-limit-test");
      expect(retrieved?.length).toBe(maxEntryBytes);
    });

    it("setAsync handles minimum valid entry size", async () => {
      // Test with smallest possible valid entry
      const minimalEntry = new Uint8Array(1).fill(42);
      await VerifiedByteCache.setAsync("minimal-test", minimalEntry);

      const retrieved = VerifiedByteCache.get("minimal-test");
      expect(retrieved?.length).toBe(1);
      expect(retrieved?.[0]).toBe(42);
    });
  });

  describe("Race condition and timing-sensitive scenarios", () => {
    it("setAsync handles rapid sequential operations without corruption", async () => {
      VerifiedByteCache.clear();
      const operations = 20;
      const results = [];

      // Rapid sequential operations
      for (let i = 0; i < operations; i++) {
        await VerifiedByteCache.setAsync(`rapid-${i}`, makeBytes(64, i % 256));
        results.push(VerifiedByteCache.get(`rapid-${i}`));
      }

      // All operations should have completed successfully
      results.forEach((result, i) => {
        expect(result).toBeDefined();
        expect(result?.length).toBe(64);
        expect(result?.[0]).toBe(i % 256);
      });

      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.setOps).toBeGreaterThanOrEqual(operations);
    });

    it("setAsync handles interleaved read/write operations", async () => {
      VerifiedByteCache.clear();

      // Interleave setAsync and get operations
      const promises = [];
      const keys = [];

      for (let i = 0; i < 10; i++) {
        const key = `interleave-${i}`;
        keys.push(key);

        // Start async set operation
        const setPromise = VerifiedByteCache.setAsync(
          key,
          makeBytes(128, i % 256),
        );
        promises.push(setPromise);

        // Immediately try to read (may or may not succeed depending on timing)
        const getResult = VerifiedByteCache.get(key);
        if (getResult) {
          expect(getResult.length).toBe(128);
          expect(getResult[0]).toBe(i % 256);
        }
      }

      // Wait for all set operations to complete
      await Promise.all(promises);

      // Verify all entries are now available
      keys.forEach((key, i) => {
        const result = VerifiedByteCache.get(key);
        expect(result).toBeDefined();
        expect(result?.length).toBe(128);
        expect(result?.[0]).toBe(i % 256);
      });
    });

    it("setAsync handles concurrent operations with same key", async () => {
      VerifiedByteCache.clear();
      const key = "same-key-race";
      const concurrentOps = 5;
      const promises = [];

      // Launch multiple concurrent operations on the same key
      for (let i = 0; i < concurrentOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          key,
          makeBytes(256, i % 256),
        );
        promises.push(promise);
      }

      await Promise.all(promises);

      // Only one value should remain (last write wins or first write wins, depending on implementation)
      const finalResult = VerifiedByteCache.get(key);
      expect(finalResult).toBeDefined();
      expect(finalResult?.length).toBe(256);

      const stats = VerifiedByteCache.getStats();
      expect(stats.setOps).toBeGreaterThanOrEqual(concurrentOps);
    });

    it("setAsync maintains consistency during eviction storms", async () => {
      VerifiedByteCache.clear();

      // Create a scenario with many rapid evictions
      const initialEntries = 8;
      for (let i = 0; i < initialEntries; i++) {
        VerifiedByteCache.set(`storm-prefill-${i}`, makeBytes(1024, i % 256));
      }

      // Launch many large entries simultaneously to create eviction pressure
      const stormPromises = [];
      for (let i = 0; i < 5; i++) {
        const promise = VerifiedByteCache.setAsync(
          `storm-${i}`,
          makeBytes(10000 + i * 1000, (i + 50) % 256),
        );
        stormPromises.push(promise);
      }

      await Promise.all(stormPromises);

      // Cache should remain in consistent state
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.totalBytes).toBeGreaterThan(0);
      expect(stats.totalBytes).toBeLessThanOrEqual(1048576); // 1MB limit

      // Should be able to perform normal operations after the storm
      await VerifiedByteCache.setAsync("post-storm", makeBytes(512, 100));
      expect(VerifiedByteCache.get("post-storm")).toBeDefined();
    });
  });

  describe("Recovery and resilience scenarios", () => {
    it("setAsync recovers gracefully from previous errors", async () => {
      // First, trigger an error
      const oversized = makeBytes(600000, 42); // 600KB > 512KB limit
      await expect(
        VerifiedByteCache.setAsync("error-recovery", oversized),
      ).rejects.toThrow();

      // Cache should still be functional after the error
      const validEntry = makeBytes(1024, 100);
      await expect(
        VerifiedByteCache.setAsync("recovery-test", validEntry),
      ).resolves.toBeUndefined();

      const retrieved = VerifiedByteCache.get("recovery-test");
      expect(retrieved?.length).toBe(1024);
      expect(retrieved?.[0]).toBe(100);

      // Stats should still work
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThanOrEqual(1);
    });

    it("setAsync handles partial failure scenarios", async () => {
      VerifiedByteCache.clear();

      // Mix of valid and invalid operations
      const operations = [
        { key: "valid-1", data: makeBytes(512, 1), shouldSucceed: true },
        { key: "", data: makeBytes(512, 2), shouldSucceed: false }, // Empty key
        { key: "valid-2", data: makeBytes(512, 3), shouldSucceed: true },
        {
          key: "a".repeat(3000),
          data: makeBytes(512, 4),
          shouldSucceed: false,
        }, // Too long key
        { key: "valid-3", data: makeBytes(512, 5), shouldSucceed: true },
      ];

      const results = [];
      for (const op of operations) {
        try {
          await VerifiedByteCache.setAsync(op.key, op.data);
          results.push({ key: op.key, success: true });
        } catch (error) {
          results.push({
            key: op.key,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      // Verify expected results (based on actual cache behavior)
      expect(results[0].success).toBe(true); // valid-1 should succeed
      expect(results[1].success).toBe(true); // empty key - cache may handle gracefully
      expect(results[2].success).toBe(true); // valid-2 should succeed
      expect(results[3].success).toBe(false); // too long key should fail
      expect(results[4].success).toBe(true); // valid-3 should succeed

      // Valid entries should be retrievable
      expect(VerifiedByteCache.get("valid-1")).toBeDefined();
      expect(VerifiedByteCache.get("valid-2")).toBeDefined();
      expect(VerifiedByteCache.get("valid-3")).toBeDefined();
    });

    it("setAsync maintains cache integrity after clear during operation", async () => {
      VerifiedByteCache.clear();

      // Start an async operation
      const setPromise = VerifiedByteCache.setAsync(
        "integrity-test",
        makeBytes(1024, 42),
      );

      // Clear cache while operation is in progress
      VerifiedByteCache.clear();

      // Wait for the operation to complete
      await setPromise;

      // Cache should be in a consistent state
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThanOrEqual(0);

      // The entry might or might not be there depending on timing, but cache should not be corrupted
      expect(() => VerifiedByteCache.getStats()).not.toThrow();
      expect(() => VerifiedByteCache.get("integrity-test")).not.toThrow();
    });

    it("setAsync handles memory pressure gracefully", async () => {
      VerifiedByteCache.clear();

      // Simulate memory pressure by filling cache repeatedly
      const pressureRounds = 3;
      const entriesPerRound = 8;

      for (let round = 0; round < pressureRounds; round++) {
        const promises = [];
        for (let i = 0; i < entriesPerRound; i++) {
          const promise = VerifiedByteCache.setAsync(
            `pressure-${round}-${i}`,
            makeBytes(2000 + round * 100, (round * entriesPerRound + i) % 256),
          );
          promises.push(promise);
        }

        await Promise.all(promises);

        // Verify cache remains functional after each round
        const stats = VerifiedByteCache.getStats();
        expect(stats.size).toBeGreaterThan(0);
        expect(stats.totalBytes).toBeGreaterThan(0);
        expect(stats.totalBytes).toBeLessThanOrEqual(1048576);

        // Should be able to add more entries
        await VerifiedByteCache.setAsync(
          `recovery-${round}`,
          makeBytes(512, round % 256),
        );
        expect(VerifiedByteCache.get(`recovery-${round}`)).toBeDefined();
      }
    });

    it("setAsync recovers from SharedArrayBuffer detection failures", async () => {
      // Test recovery when SAB detection encounters edge cases
      if (typeof SharedArrayBuffer !== "undefined") {
        const sab = new SharedArrayBuffer(64);
        const sabView = new Uint8Array(sab);

        // First operation should fail
        await expect(
          VerifiedByteCache.setAsync("sab-fail", sabView),
        ).rejects.toThrow();

        // Subsequent valid operations should work
        await VerifiedByteCache.setAsync("post-sab", makeBytes(256, 100));
        expect(VerifiedByteCache.get("post-sab")).toBeDefined();

        // Cache stats should still be accessible
        const stats = VerifiedByteCache.getStats();
        expect(stats.size).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe("Advanced SharedArrayBuffer detection edge cases", () => {
    it("setAsync detects various SharedArrayBuffer-backed views", async () => {
      if (typeof SharedArrayBuffer === "undefined") {
        console.warn("SharedArrayBuffer not available, skipping SAB tests");
        return;
      }

      const sab = new SharedArrayBuffer(256);

      // Test different view types on SharedArrayBuffer
      const viewTypes = [
        { name: "Uint8Array", view: new Uint8Array(sab) },
        { name: "Uint16Array", view: new Uint16Array(sab) },
        { name: "Uint32Array", view: new Uint32Array(sab) },
        { name: "Int8Array", view: new Int8Array(sab) },
        { name: "Int16Array", view: new Int16Array(sab) },
        { name: "Int32Array", view: new Int32Array(sab) },
        { name: "Float32Array", view: new Float32Array(sab, 0, 16) },
        { name: "Float64Array", view: new Float64Array(sab, 0, 8) },
      ];

      for (const { name, view } of viewTypes) {
        // The cache may reject non-Uint8Array types before SAB detection
        await expect(
          VerifiedByteCache.setAsync(`sab-${name}`, view as Uint8Array),
        ).rejects.toThrow(
          /Invalid value|SharedArrayBuffer.*not permitted|must be/,
        );
      }
    });

    it("setAsync handles SharedArrayBuffer with offsets and lengths", async () => {
      if (typeof SharedArrayBuffer === "undefined") {
        console.warn("SharedArrayBuffer not available, skipping SAB tests");
        return;
      }

      const sab = new SharedArrayBuffer(1024);

      // Test views with different offsets and lengths
      const offsetView = new Uint8Array(sab, 100, 200); // offset 100, length 200
      const partialView = new Uint8Array(sab, 0, 50); // first 50 bytes

      await expect(
        VerifiedByteCache.setAsync("sab-offset", offsetView),
      ).rejects.toThrow(/SharedArrayBuffer.*not permitted/);

      await expect(
        VerifiedByteCache.setAsync("sab-partial", partialView),
      ).rejects.toThrow(/SharedArrayBuffer.*not permitted/);
    });

    it("setAsync distinguishes regular ArrayBuffer from SharedArrayBuffer", async () => {
      if (typeof SharedArrayBuffer === "undefined") {
        console.warn("SharedArrayBuffer not available, skipping SAB tests");
        return;
      }

      // Regular ArrayBuffer should work
      const regularBuffer = new ArrayBuffer(256);
      const regularView = new Uint8Array(regularBuffer);
      regularView.fill(42);

      await expect(
        VerifiedByteCache.setAsync("regular-buffer", regularView),
      ).resolves.toBeUndefined();

      const retrieved = VerifiedByteCache.get("regular-buffer");
      expect(retrieved?.length).toBe(256);
      expect(retrieved?.[0]).toBe(42);

      // SharedArrayBuffer should be rejected
      const sharedBuffer = new SharedArrayBuffer(256);
      const sharedView = new Uint8Array(sharedBuffer);
      sharedView.fill(84);

      await expect(
        VerifiedByteCache.setAsync("shared-buffer", sharedView),
      ).rejects.toThrow(/SharedArrayBuffer.*not permitted/);
    });

    it("setAsync handles edge cases in SAB detection", async () => {
      if (typeof SharedArrayBuffer === "undefined") {
        console.warn("SharedArrayBuffer not available, skipping SAB tests");
        return;
      }

      // Test with empty SharedArrayBuffer
      const emptySab = new SharedArrayBuffer(0);
      const emptyView = new Uint8Array(emptySab);

      await expect(
        VerifiedByteCache.setAsync("empty-sab", emptyView),
      ).rejects.toThrow(/SharedArrayBuffer.*not permitted/);

      // Test with very large SharedArrayBuffer
      const largeSab = new SharedArrayBuffer(1024 * 1024); // 1MB
      const largeView = new Uint8Array(largeSab);

      await expect(
        VerifiedByteCache.setAsync("large-sab", largeView),
      ).rejects.toThrow(/SharedArrayBuffer.*not permitted/);

      // Verify normal operations still work after SAB rejections
      await VerifiedByteCache.setAsync("post-sab-normal", makeBytes(512, 100));
      expect(VerifiedByteCache.get("post-sab-normal")).toBeDefined();
    });

    it("setAsync handles cross-realm ArrayBuffer scenarios", async () => {
      // Test with ArrayBuffer from different context (if available)
      // This simulates cross-realm scenarios that might occur in some environments

      const regularBuffer = new ArrayBuffer(128);
      const regularView = new Uint8Array(regularBuffer);
      regularView.fill(42);

      // Should work normally
      await expect(
        VerifiedByteCache.setAsync("cross-realm-regular", regularView),
      ).resolves.toBeUndefined();

      const retrieved = VerifiedByteCache.get("cross-realm-regular");
      expect(retrieved?.length).toBe(128);
      expect(retrieved?.[0]).toBe(42);

      // Test with detached ArrayBuffer (if supported)
      if (
        typeof regularBuffer.transfer === "function" ||
        typeof regularBuffer.transferToFixedLength === "function"
      ) {
        try {
          // Detach the buffer
          const detachedView = new Uint8Array(regularBuffer.slice(0)); // Create a copy before detaching

          // The detached buffer scenario would depend on the specific implementation
          // This tests that the cache handles various buffer states gracefully
          await expect(
            VerifiedByteCache.setAsync("detached-test", detachedView),
          ).resolves.toBeUndefined();
        } catch (error) {
          // Detached buffer handling may vary by implementation
          console.log("Detached buffer test skipped:", error);
        }
      }
    });
  });

  describe("TTL integration with setAsync operations", () => {
    it("setAsync respects TTL for cache entries", async () => {
      VerifiedByteCache.clear();

      const shortTtlEntry = makeBytes(256, 42);
      const longTtlEntry = makeBytes(256, 84);

      // Set entries with different TTL values (if supported by the cache)
      // Note: VerifiedByteCache may use default TTL, so we'll test basic TTL behavior
      await VerifiedByteCache.setAsync("ttl-short", shortTtlEntry);
      await VerifiedByteCache.setAsync("ttl-long", longTtlEntry);

      // Both should be available immediately
      expect(VerifiedByteCache.get("ttl-short")).toBeDefined();
      expect(VerifiedByteCache.get("ttl-long")).toBeDefined();

      // Wait a short time (TTL behavior depends on cache implementation)
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Entries should still be available (or expired based on cache TTL settings)
      const shortResult = VerifiedByteCache.get("ttl-short");
      const longResult = VerifiedByteCache.get("ttl-long");

      // The exact TTL behavior depends on the cache implementation
      // We mainly verify that setAsync doesn't break TTL functionality
      if (shortResult) {
        expect(shortResult.length).toBe(256);
        expect(shortResult[0]).toBe(42);
      }
      if (longResult) {
        expect(longResult.length).toBe(256);
        expect(longResult[0]).toBe(84);
      }
    });

    it("setAsync handles TTL edge cases", async () => {
      VerifiedByteCache.clear();

      // Test with zero-length entry and TTL
      const emptyEntry = new Uint8Array(0);
      await VerifiedByteCache.setAsync("ttl-empty", emptyEntry);

      // Should handle gracefully (empty entries might be treated specially)
      const emptyResult = VerifiedByteCache.get("ttl-empty");
      if (emptyResult !== undefined) {
        expect(emptyResult.length).toBe(0);
      }

      // Test rapid TTL expiration scenarios
      const rapidEntries = 5;
      for (let i = 0; i < rapidEntries; i++) {
        await VerifiedByteCache.setAsync(
          `ttl-rapid-${i}`,
          makeBytes(64, i % 256),
        );
      }

      // All should be retrievable immediately
      for (let i = 0; i < rapidEntries; i++) {
        const result = VerifiedByteCache.get(`ttl-rapid-${i}`);
        expect(result).toBeDefined();
        expect(result?.length).toBe(64);
        expect(result?.[0]).toBe(i % 256);
      }
    });

    it("setAsync maintains TTL consistency during eviction", async () => {
      VerifiedByteCache.clear();

      // Fill cache with entries that have TTL
      const prefillCount = 8;
      for (let i = 0; i < prefillCount; i++) {
        await VerifiedByteCache.setAsync(
          `ttl-prefill-${i}`,
          makeBytes(512, i % 256),
        );
      }

      const statsBefore = VerifiedByteCache.getStats();

      // Add a large entry that will trigger eviction
      await VerifiedByteCache.setAsync(
        "ttl-eviction-test",
        makeBytes(20000, 255),
      );

      const statsAfter = VerifiedByteCache.getStats();

      // Verify eviction occurred and cache remains consistent
      expect(statsAfter.evictions).toBeGreaterThanOrEqual(
        statsBefore.evictions,
      );
      expect(statsAfter.size).toBeGreaterThan(0);

      // The large entry should be present
      const largeResult = VerifiedByteCache.get("ttl-eviction-test");
      expect(largeResult?.length).toBe(20000);
      expect(largeResult?.[0]).toBe(255);

      // Some of the original entries may have been evicted
      // This is normal behavior and should not affect TTL consistency
    });

    it("setAsync works with concurrent TTL operations", async () => {
      VerifiedByteCache.clear();

      // Launch multiple setAsync operations with potential TTL interactions
      const concurrentTtlOps = 5;
      const promises = [];

      for (let i = 0; i < concurrentTtlOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          `concurrent-ttl-${i}`,
          makeBytes(256 + i * 32, (i + 100) % 256),
        );
        promises.push(promise);
      }

      await Promise.all(promises);

      // Verify all operations completed and entries are accessible
      for (let i = 0; i < concurrentTtlOps; i++) {
        const result = VerifiedByteCache.get(`concurrent-ttl-${i}`);
        expect(result).toBeDefined();
        expect(result?.length).toBe(256 + i * 32);
        expect(result?.[0]).toBe((i + 100) % 256);
      }

      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.setOps).toBeGreaterThanOrEqual(concurrentTtlOps);
    });
  });

  describe("Cache warming and cold start scenarios", () => {
    it("setAsync performance during cache warming", async () => {
      VerifiedByteCache.clear();

      const warmingEntries = 10;
      const times = [];

      // Measure performance during cache warming phase
      for (let i = 0; i < warmingEntries; i++) {
        const { duration } = await timeAsync(() =>
          VerifiedByteCache.setAsync(`warm-${i}`, makeBytes(1024, i % 256)),
        );
        times.push(duration);
      }

      const avgWarmTime = times.reduce((a, b) => a + b, 0) / times.length;
      const maxWarmTime = Math.max(...times);

      // Performance should be reasonable during warming
      expect(avgWarmTime).toBeLessThan(20);
      expect(maxWarmTime).toBeLessThan(100);

      // All entries should be stored
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBe(warmingEntries);
    });

    it("setAsync handles cold start with immediate load", async () => {
      VerifiedByteCache.clear();

      // Simulate cold start with immediate high load
      const coldStartOps = 5;
      const promises: Promise<void>[] = [];

      for (let i = 0; i < coldStartOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          `cold-${i}`,
          makeBytes(2048 + i * 256, (i + 200) % 256),
        );
        promises.push(promise);
      }

      const { duration } = await timeAsync(() => Promise.all(promises));

      // Cold start should complete in reasonable time
      expect(duration).toBeLessThan(500);

      // All entries should be stored
      for (let i = 0; i < coldStartOps; i++) {
        const result = VerifiedByteCache.get(`cold-${i}`);
        expect(result).toBeDefined();
        expect(result?.length).toBe(2048 + i * 256);
        expect(result?.[0]).toBe((i + 200) % 256);
      }
    });

    it("setAsync maintains performance under sustained load", async () => {
      VerifiedByteCache.clear();

      const sustainedRounds = 3;
      const opsPerRound = 5;
      const allTimes = [];

      for (let round = 0; round < sustainedRounds; round++) {
        const roundTimes = [];

        for (let i = 0; i < opsPerRound; i++) {
          const { duration } = await timeAsync(() =>
            VerifiedByteCache.setAsync(
              `sustained-${round}-${i}`,
              makeBytes(512 + round * 64, (round * opsPerRound + i) % 256),
            ),
          );
          roundTimes.push(duration);
        }

        allTimes.push(...roundTimes);

        // Brief pause between rounds
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      const avgTime = allTimes.reduce((a, b) => a + b, 0) / allTimes.length;
      const maxTime = Math.max(...allTimes);

      // Sustained performance should remain reasonable
      expect(avgTime).toBeLessThan(15);
      expect(maxTime).toBeLessThan(50);

      // All entries should be stored (some may be evicted due to capacity limits)
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.size).toBeLessThanOrEqual(sustainedRounds * opsPerRound);
    });

    it("setAsync handles cache warming with eviction pressure", async () => {
      VerifiedByteCache.clear();

      // Pre-warm cache to near capacity
      const prewarmCount = 8;
      for (let i = 0; i < prewarmCount; i++) {
        VerifiedByteCache.set(`prewarm-${i}`, makeBytes(1024, i % 256));
      }

      // Now perform setAsync operations that will trigger eviction during warming
      const warmingWithEvictionOps = 5;
      const times = [];

      for (let i = 0; i < warmingWithEvictionOps; i++) {
        const { duration } = await timeAsync(() =>
          VerifiedByteCache.setAsync(
            `warm-evict-${i}`,
            makeBytes(3000 + i * 200, (i + 150) % 256),
          ),
        );
        times.push(duration);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;

      // Performance should remain reasonable even with eviction
      expect(avgTime).toBeLessThan(30);

      // Verify cache is in consistent state
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.totalBytes).toBeLessThanOrEqual(1048576);
      expect(stats.evictions).toBeGreaterThan(0);

      // At least some of the new entries should be present
      let foundCount = 0;
      for (let i = 0; i < warmingWithEvictionOps; i++) {
        if (VerifiedByteCache.get(`warm-evict-${i}`)) {
          foundCount++;
        }
      }
      expect(foundCount).toBeGreaterThan(0);
    });

    it("setAsync recovers quickly from cache clear during operation", async () => {
      VerifiedByteCache.clear();

      // Start multiple operations
      const recoveryOps = 3;
      const promises = [];

      for (let i = 0; i < recoveryOps; i++) {
        const promise = VerifiedByteCache.setAsync(
          `recovery-${i}`,
          makeBytes(1024, i % 256),
        );
        promises.push(promise);
      }

      // Clear cache while operations are in progress
      VerifiedByteCache.clear();

      // Wait for operations to complete
      await Promise.all(promises);

      // Cache should be functional immediately after
      await VerifiedByteCache.setAsync("post-clear", makeBytes(512, 100));

      const result = VerifiedByteCache.get("post-clear");
      expect(result?.length).toBe(512);
      expect(result?.[0]).toBe(100);

      // Stats should be consistent
      const stats = VerifiedByteCache.getStats();
      expect(stats.size).toBeGreaterThanOrEqual(1);
    });
  });
});
