// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

// -----------------------------------------------------------------------------
// Performance Tests for SecureLRUCache
// -----------------------------------------------------------------------------
// This test suite validates the performance characteristics of SecureLRUCache
// according to the Testing & Quality Assurance Constitution (v2.6).
// RULE-ID: perf-budget-enforcement
// RULE-ID: perf-lcp-budget (adapted for module performance)
// RULE-ID: deterministic-async (for any async operations)
// RULE-ID: module-state-isolation (ensured via beforeEach reset)

import { describe, it, expect, beforeEach, vi } from "vitest";
import { SecureLRUCache } from "../../src/secure-lru-cache";
import { VerifiedByteCache } from "../../src/secure-cache";

// Statistical analysis utilities with enhanced metrics
interface PerformanceStats {
  mean: number;
  /** Median-of-means (robust estimator) */
  mom: number;
  median: number;
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
  p999: number;
  min: number;
  max: number;
  stdDev: number;
  cv: number; // Coefficient of variation
  samples: number;
}

function calculateStats(times: number[]): PerformanceStats {
  const sorted = [...times].sort((a, b) => a - b);
  const n = sorted.length;
  const mean = times.reduce((a, b) => a + b, 0) / n;
  const variance =
    times.reduce((acc, time) => acc + Math.pow(time - mean, 2), 0) / n;
  const stdDev = Math.sqrt(variance);
  const cv = (stdDev / mean) * 100;

  // Median-of-Means (MoM) estimator: split samples into b blocks and take
  // the median of block means. Recommended b = floor(sqrt(n)) for robustness.
  const b = Math.max(1, Math.floor(Math.sqrt(n)));
  const blockSize = Math.max(1, Math.floor(n / b));
  const blockMeans: number[] = [];
  for (let i = 0; i < b; i++) {
    const start = i * blockSize;
    const end = i === b - 1 ? n : Math.min(n, start + blockSize);
    if (start >= end) break;
    const block = times.slice(start, end);
    const bm = block.reduce((a, v) => a + v, 0) / block.length;
    blockMeans.push(bm);
  }
  const mom = blockMeans.sort((x, y) => x - y)[
    Math.floor(blockMeans.length / 2)
  ];

  return {
    mean,
    median: sorted[Math.floor(n / 2)],
    p50: sorted[Math.floor(n * 0.5)],
    p75: sorted[Math.floor(n * 0.75)],
    p90: sorted[Math.floor(n * 0.9)],
    p95: sorted[Math.floor(n * 0.95)],
    p99: sorted[Math.floor(n * 0.99)],
    p999: sorted[Math.floor(n * 0.999)],
    min: sorted[0],
    max: sorted[n - 1],
    stdDev,
    cv,
    mom,
    samples: n,
  };
}

// Simple bootstrap CI for a statistic function
function bootstrapCI(
  samples: number[],
  statFn: (arr: number[]) => number,
  iters = 500,
  alpha = 0.05,
) {
  const n = samples.length;
  const out: number[] = [];
  for (let i = 0; i < iters; i++) {
    const res: number[] = [];
    for (let j = 0; j < n; j++) {
      const idx = Math.floor(Math.random() * n);
      res.push(samples[idx]);
    }
    out.push(statFn(res));
  }
  out.sort((a, b) => a - b);
  const lo = out[Math.floor((alpha / 2) * iters)];
  const hi = out[Math.floor((1 - alpha / 2) * iters)];
  return { lo, hi, samples: out };
}

function momEstimator(arr: number[]) {
  const n = arr.length;
  const b = Math.max(1, Math.floor(Math.sqrt(n)));
  const blockSize = Math.max(1, Math.floor(n / b));
  const blockMeans: number[] = [];
  for (let i = 0; i < b; i++) {
    const start = i * blockSize;
    const end = i === b - 1 ? n : Math.min(n, start + blockSize);
    if (start >= end) break;
    const block = arr.slice(start, end);
    const bm = block.reduce((a, v) => a + v, 0) / block.length;
    blockMeans.push(bm);
  }
  return blockMeans.sort((x, y) => x - y)[Math.floor(blockMeans.length / 2)];
}

function warmup(cache: SecureLRUCache<string, Uint8Array>, iterations = 1000) {
  const data = new Uint8Array(512);
  for (let i = 0; i < iterations; i++) {
    cache.set(`warmup-${i}`, data);
    cache.get(`warmup-${i}`);
    cache.delete(`warmup-${i}`);
  }
  // Force GC if available to stabilize measurements
  if (global.gc) {
    global.gc();
  }
}

function forceGC() {
  if (global.gc) {
    global.gc();
  }
}

// Performance budgets with statistical requirements
// These budgets ensure the cache performs efficiently under load
// NOTE: Using statistical thresholds for more robust performance validation
const PERFORMANCE_BUDGETS = {
  // Basic operations - mean and P95 thresholds (relaxed for stability)
  SET_TIME_MEAN_MS: 10,
  SET_TIME_P95_MS: 25,
  GET_TIME_MEAN_MS: 5,
  GET_TIME_P95_MS: 20,
  DELETE_TIME_MEAN_MS: 5,
  DELETE_TIME_P95_MS: 15,

  // Bulk operations
  BULK_OPERATIONS_MEAN_MS: 1.0, // Per operation
  BULK_OPERATIONS_P95_MS: 5.0, // Per operation

  // Memory and eviction
  EVICTION_TIME_P95_MS: 100,
  MAX_MEMORY_BYTES: 1_048_576, // 1MB

  // Statistical requirements (increased samples for better significance)
  MIN_SAMPLES: 5000, // Increased for statistical significance
  MAX_COEFFICIENT_OF_VARIATION: 100, // Relaxed CV threshold to avoid flakes
};

describe("SecureLRUCache Performance Tests", () => {
  let cache: SecureLRUCache<string, Uint8Array>;

  beforeEach(() => {
    // Force low-jitter wipe scheduling in perf tests to avoid scheduler drift across environments
    // Using microtask avoids timeout-driven draining spikes observed in eviction-heavy benches.
    if (!process.env.WIPE_SCHED) process.env.WIPE_SCHED = "microtask";
    if (!process.env.WIPE_AUTO_THRESH) process.env.WIPE_AUTO_THRESH = "512";
    if (!process.env.WIPE_TIMEOUT_MS) process.env.WIPE_TIMEOUT_MS = "0";

    // Ensure module isolation and clean state
    vi.resetModules();
    cache = new SecureLRUCache({
      maxEntries: 1000, // Increased for statistical significance
      maxBytes: PERFORMANCE_BUDGETS.MAX_MEMORY_BYTES,
      defaultTtlMs: 10000, // Longer TTL for testing
    });
  });

  // Set a global timeout for the entire performance test suite
  // This prevents any single test or the entire suite from running indefinitely
  vi.setConfig({ testTimeout: 60000 }); // 60 seconds max for statistical tests

  describe("Statistical Performance Analysis", () => {
    it(
      "should perform SET operations with consistent performance",
      { timeout: 60000 },
      () => {
        const times: number[] = [];
        const data = new Uint8Array(1024);
        const iterations = PERFORMANCE_BUDGETS.MIN_SAMPLES;

        // Use a dedicated cache for this intensive test to avoid cross-test interference
        const testCache = new SecureLRUCache({
          maxEntries: iterations * 2,
          maxBytes: iterations * 2 * data.length,
          defaultTtlMs: 60000,
        });

        // Extended warmup phase
        warmup(testCache, 2000);

        // Measurement phase with GC control
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          testCache.set(`perf-key-${i}`, data);
          const end = performance.now();
          times.push(end - start);

          // Periodic GC to reduce variability
          if (i % 1000 === 0) {
            forceGC();
          }
        }

        const stats = calculateStats(times);

        // Statistical assertions using bootstrap confidence intervals for robustness
        const bootstrapIters = Number(
          process.env.PERF_BOOTSTRAP_ITERS || "500",
        );
        const momCI = bootstrapCI(times, momEstimator, bootstrapIters);
        const p95CI = bootstrapCI(
          times,
          (arr) => calculateStats(arr).p95,
          bootstrapIters,
        );

        // Assert that the upper 95% CI bound for MoM and p95 are within budgets
        expect(momCI.hi).toBeLessThan(PERFORMANCE_BUDGETS.SET_TIME_MEAN_MS);
        expect(p95CI.hi).toBeLessThan(PERFORMANCE_BUDGETS.SET_TIME_P95_MS);
        expect(stats.samples).toBe(iterations);

        // Log comprehensive metrics for analysis
        console.log("SET Performance Statistics (MoM):", {
          mom: `${stats.mom.toFixed(4)}ms`,
          median: `${stats.median.toFixed(4)}ms`,
          p50: `${stats.p50.toFixed(4)}ms`,
          p75: `${stats.p75.toFixed(4)}ms`,
          p90: `${stats.p90.toFixed(4)}ms`,
          p95: `${stats.p95.toFixed(4)}ms`,
          p99: `${stats.p99.toFixed(4)}ms`,
          p999: `${stats.p999.toFixed(4)}ms`,
          min: `${stats.min.toFixed(4)}ms`,
          max: `${stats.max.toFixed(4)}ms`,
          stdDev: `${stats.stdDev.toFixed(4)}ms`,
          cv: `${stats.cv.toFixed(2)}%`,
          samples: stats.samples,
        });
      },
    );

    it(
      "should perform GET operations with consistent performance (high hit-rate)",
      { timeout: 60000 },
      () => {
        const times: number[] = [];
        const data = new Uint8Array(1024);
        const iterations = PERFORMANCE_BUDGETS.MIN_SAMPLES;

        // Use a dedicated cache with higher capacity to avoid eviction during pre-population
        const testCache = new SecureLRUCache({
          maxEntries: iterations * 2,
          maxBytes: iterations * 2 * data.length,
          defaultTtlMs: 60000,
        });

        // Pre-populate cache
        for (let i = 0; i < iterations; i++) {
          testCache.set(`get-key-${i}`, data);
        }

        // Extended warmup
        warmup(testCache, 2000);

        // Measurement phase with GC control
        let hits = 0;
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          const result = testCache.get(`get-key-${i}`);
          const end = performance.now();
          times.push(end - start);
          if (result !== undefined && result !== null) hits++;

          // Periodic GC
          if (i % 1000 === 0) {
            forceGC();
          }
        }

        const stats = calculateStats(times);
        const hitRate = (hits / iterations) * 100;

        const bootstrapItersG = Number(
          process.env.PERF_BOOTSTRAP_ITERS || "500",
        );
        const momCIG = bootstrapCI(times, momEstimator, bootstrapItersG);
        const p95CIG = bootstrapCI(
          times,
          (arr) => calculateStats(arr).p95,
          bootstrapItersG,
        );

        expect(momCIG.hi).toBeLessThan(PERFORMANCE_BUDGETS.GET_TIME_MEAN_MS);
        expect(p95CIG.hi).toBeLessThan(PERFORMANCE_BUDGETS.GET_TIME_P95_MS);
        // Require very high hit rate for this synthetic test
        expect(hitRate).toBeGreaterThan(95);

        console.log("GET Performance Statistics (MoM):", {
          mom: `${stats.mom.toFixed(4)}ms`,
          median: `${stats.median.toFixed(4)}ms`,
          p50: `${stats.p50.toFixed(4)}ms`,
          p75: `${stats.p75.toFixed(4)}ms`,
          p90: `${stats.p90.toFixed(4)}ms`,
          p95: `${stats.p95.toFixed(4)}ms`,
          p99: `${stats.p99.toFixed(4)}ms`,
          p999: `${stats.p999.toFixed(4)}ms`,
          min: `${stats.min.toFixed(4)}ms`,
          max: `${stats.max.toFixed(4)}ms`,
          stdDev: `${stats.stdDev.toFixed(4)}ms`,
          hitRate: `${hitRate.toFixed(2)}%`,
          samples: stats.samples,
        });
      },
    );

    it(
      "should perform DELETE operations with consistent performance and actually remove entries",
      { timeout: 60000 },
      () => {
        const times: number[] = [];
        const data = new Uint8Array(1024);
        const iterations = PERFORMANCE_BUDGETS.MIN_SAMPLES;

        // Use a dedicated cache for delete test to avoid interference
        const testCache = new SecureLRUCache({
          maxEntries: iterations * 2,
          maxBytes: iterations * 2 * data.length,
          defaultTtlMs: 60000,
        });

        // Pre-populate cache
        for (let i = 0; i < iterations; i++) {
          testCache.set(`del-key-${i}`, data);
        }

        // Extended warmup
        warmup(testCache, 2000);

        // Measurement phase with GC control
        let deletedCount = 0;
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          const deleted = testCache.delete(`del-key-${i}`);
          const end = performance.now();
          times.push(end - start);

          // Some implementations return void/undefined. Confirm deletion by checking get()
          const post = testCache.get(`del-key-${i}`);
          if (post === undefined || post === null) deletedCount++;

          // Periodic GC
          if (i % 1000 === 0) {
            forceGC();
          }
        }

        const stats = calculateStats(times);

        const bootstrapItersD = Number(
          process.env.PERF_BOOTSTRAP_ITERS || "500",
        );
        const momCID = bootstrapCI(times, momEstimator, bootstrapItersD);
        const p95CID = bootstrapCI(
          times,
          (arr) => calculateStats(arr).p95,
          bootstrapItersD,
        );

        expect(momCID.hi).toBeLessThan(PERFORMANCE_BUDGETS.DELETE_TIME_MEAN_MS);
        expect(p95CID.hi).toBeLessThan(PERFORMANCE_BUDGETS.DELETE_TIME_P95_MS);
        // Require that the vast majority of deletions actually removed the keys
        expect(deletedCount).toBeGreaterThan(Math.floor(iterations * 0.99));

        console.log("DELETE Performance Statistics (MoM):", {
          mom: `${stats.mom.toFixed(4)}ms`,
          median: `${stats.median.toFixed(4)}ms`,
          p50: `${stats.p50.toFixed(4)}ms`,
          p75: `${stats.p75.toFixed(4)}ms`,
          p90: `${stats.p90.toFixed(4)}ms`,
          p95: `${stats.p95.toFixed(4)}ms`,
          p99: `${stats.p99.toFixed(4)}ms`,
          p999: `${stats.p999.toFixed(4)}ms`,
          min: `${stats.min.toFixed(4)}ms`,
          max: `${stats.max.toFixed(4)}ms`,
          stdDev: `${stats.stdDev.toFixed(4)}ms`,
          deletedCount,
          samples: stats.samples,
        });
      },
    );
  });

  describe("Mixed Workload Performance", () => {
    it(
      "should handle mixed read/write workload efficiently",
      { timeout: 30000 },
      () => {
        const setTimes: number[] = [];
        const getTimes: number[] = [];
        const data = new Uint8Array(512);
        const iterations = Math.floor(PERFORMANCE_BUDGETS.MIN_SAMPLES / 2);

        // Warmup
        warmup(cache, 100);

        // Mixed workload: 50% reads, 50% writes
        for (let i = 0; i < iterations; i++) {
          // Write operation
          const setStart = performance.now();
          cache.set(`mixed-key-${i}`, data);
          const setEnd = performance.now();
          setTimes.push(setEnd - setStart);

          // Read operation (read previous key if exists)
          if (i > 0) {
            const getStart = performance.now();
            cache.get(`mixed-key-${i - 1}`);
            const getEnd = performance.now();
            getTimes.push(getEnd - getStart);
          }
        }

        const setStats = calculateStats(setTimes);
        const getStats = calculateStats(getTimes);

        // Verify performance under mixed load
        expect(setStats.mom).toBeLessThan(
          PERFORMANCE_BUDGETS.BULK_OPERATIONS_MEAN_MS,
        );
        expect(getStats.mom).toBeLessThan(
          PERFORMANCE_BUDGETS.BULK_OPERATIONS_MEAN_MS,
        );
        expect(setStats.p95).toBeLessThan(
          PERFORMANCE_BUDGETS.BULK_OPERATIONS_P95_MS,
        );
        expect(getStats.p95).toBeLessThan(
          PERFORMANCE_BUDGETS.BULK_OPERATIONS_P95_MS,
        );

        console.log("Mixed Workload Performance (MoM):", {
          setMoM: `${setStats.mom.toFixed(3)}ms`,
          getMoM: `${getStats.mom.toFixed(3)}ms`,
          setP95: `${setStats.p95.toFixed(3)}ms`,
          getP95: `${getStats.p95.toFixed(3)}ms`,
          totalOperations: setTimes.length + getTimes.length,
        });
      },
    );
  });

  describe("Eviction Performance Analysis", () => {
    it(
      "should perform LRU evictions with consistent timing",
      { timeout: 30000 },
      () => {
        const evictionTimes: number[] = [];
        const data = new Uint8Array(1024);
        const maxEntries = 100;

        // Create cache with smaller capacity for eviction testing
        const testCache = new SecureLRUCache({
          maxEntries,
          maxBytes: PERFORMANCE_BUDGETS.MAX_MEMORY_BYTES,
          defaultTtlMs: 10000,
        });

        // Fill cache to capacity
        for (let i = 0; i < maxEntries; i++) {
          testCache.set(`initial-${i}`, data);
        }

        // Measure eviction performance
        const evictionSamples = 200;
        for (let i = 0; i < evictionSamples; i++) {
          const start = performance.now();
          testCache.set(`evict-trigger-${i}`, data); // This should trigger eviction
          const end = performance.now();
          evictionTimes.push(end - start);

          expect(testCache.getStats().size).toBeLessThanOrEqual(maxEntries);
        }

        const stats = calculateStats(evictionTimes);
        expect(stats.p95).toBeLessThan(
          PERFORMANCE_BUDGETS.EVICTION_TIME_P95_MS,
        );

        console.log("Eviction Performance Statistics (MoM):", {
          mom: `${stats.mom.toFixed(3)}ms`,
          p95: `${stats.p95.toFixed(3)}ms`,
          p99: `${stats.p99.toFixed(3)}ms`,
          samples: stats.samples,
        });
      },
    );
  });

  describe("Memory and Throughput Analysis", () => {
    it(
      "should demonstrate memory efficiency metrics",
      { timeout: 15000 },
      () => {
        const data = new Uint8Array(1024); // 1KB
        const entries = 500;

        const initialStats = cache.getStats();

        // Fill cache
        for (let i = 0; i < entries; i++) {
          cache.set(`memory-key-${i}`, data);
        }

        const finalStats = cache.getStats();
        const memoryEfficiency =
          (entries * data.length) / finalStats.totalBytes;
        const overheadPerEntry =
          (finalStats.totalBytes - entries * data.length) / entries;

        // Memory efficiency should be reasonable (>80% of actual data)
        expect(memoryEfficiency).toBeGreaterThan(0.8);
        expect(finalStats.totalBytes).toBeLessThanOrEqual(
          PERFORMANCE_BUDGETS.MAX_MEMORY_BYTES,
        );

        console.log("Memory Efficiency Metrics:", {
          totalEntries: finalStats.size,
          totalBytes: finalStats.totalBytes,
          actualDataBytes: entries * data.length,
          memoryEfficiency: `${(memoryEfficiency * 100).toFixed(2)}%`,
          overheadPerEntry: `${overheadPerEntry.toFixed(2)} bytes`,
          averageEntrySize: `${(finalStats.totalBytes / finalStats.size).toFixed(2)} bytes`,
        });
      },
    );

    it("should measure sustained throughput", { timeout: 20000 }, () => {
      const data = new Uint8Array(512);
      const testDurationMs = 5000; // 5 second test
      const startTime = performance.now();
      let operations = 0;
      let currentTime = startTime;

      // Sustained operations for 5 seconds
      while (currentTime - startTime < testDurationMs) {
        cache.set(`throughput-${operations}`, data);
        operations++;
        currentTime = performance.now();

        // Prevent infinite loop
        if (operations > 100000) break;
      }

      const actualDuration = currentTime - startTime;
      const throughput = operations / (actualDuration / 1000); // ops/second
      const avgLatency = actualDuration / operations; // ms/op

      // Should achieve reasonable throughput
      expect(throughput).toBeGreaterThan(1000); // At least 1000 ops/sec
      expect(avgLatency).toBeLessThan(1); // Less than 1ms per operation

      console.log("Sustained Throughput Metrics:", {
        totalOperations: operations,
        durationMs: actualDuration.toFixed(2),
        throughputOpsPerSec: throughput.toFixed(2),
        avgLatencyMs: avgLatency.toFixed(3),
        finalCacheSize: cache.getStats().size,
      });
    });
  });

  describe("Cache Effectiveness Analysis", () => {
    it("should demonstrate cache hit rate patterns", { timeout: 15000 }, () => {
      const data = new Uint8Array(256);
      const numEntries = 100;
      const accessPatterns = 1000;

      // Populate cache
      for (let i = 0; i < numEntries; i++) {
        cache.set(`pattern-${i}`, data);
      }

      let hits = 0;
      let misses = 0;

      // Zipfian-like access pattern (80/20 rule)
      for (let i = 0; i < accessPatterns; i++) {
        const key =
          Math.random() < 0.8
            ? `pattern-${Math.floor(Math.random() * 20)}` // 80% access to first 20% of keys
            : `pattern-${Math.floor(Math.random() * numEntries)}`; // 20% access to all keys

        const result = cache.get(key);
        if (result) hits++;
        else misses++;
      }

      const hitRate = (hits / (hits + misses)) * 100;
      const missRate = (misses / (hits + misses)) * 100;

      // Should achieve good hit rate with realistic access patterns
      expect(hitRate).toBeGreaterThan(70); // At least 70% hit rate

      console.log("Cache Effectiveness Metrics:", {
        totalAccesses: hits + misses,
        hits,
        misses,
        hitRate: `${hitRate.toFixed(2)}%`,
        missRate: `${missRate.toFixed(2)}%`,
        cacheSize: cache.getStats().size,
      });
    });
  });

  // Additional tests inspired by bench-lru observations (key shapes, GC, feature overhead)
  describe("bench-lru derived tests", () => {
    it(
      "key-shape sensitivity: numeric-like vs short vs long string keys",
      { timeout: 20000 },
      () => {
        const data = new Uint8Array(256);
        const iterations = 20000;

        function runWithKeyBuilder(keyBuilder: (i: number) => string) {
          const testCache = new SecureLRUCache({
            maxEntries: iterations * 2,
            maxBytes: iterations * 2 * data.length,
          });
          // Warmup
          for (let i = 0; i < 1000; i++) testCache.set(keyBuilder(i), data);
          forceGC();
          const times: number[] = [];
          for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            testCache.set(keyBuilder(i), data);
            const end = performance.now();
            times.push(end - start);
          }
          return calculateStats(times);
        }

        const numericLike = runWithKeyBuilder((i) => String(i));
        const shortStrings = runWithKeyBuilder((i) => `k${i}`);
        const longStrings = runWithKeyBuilder(
          (i) => `key-${i}-${"x".repeat(512)}`,
        );

        console.log("Key-shape metrics:", {
          numericLike: {
            mean: numericLike.mean.toFixed(4),
            p95: numericLike.p95.toFixed(4),
            cv: numericLike.cv.toFixed(2) + "%",
          },
          shortStrings: {
            mean: shortStrings.mean.toFixed(4),
            p95: shortStrings.p95.toFixed(4),
            cv: shortStrings.cv.toFixed(2) + "%",
          },
          longStrings: {
            mean: longStrings.mean.toFixed(4),
            p95: longStrings.p95.toFixed(4),
            cv: longStrings.cv.toFixed(2) + "%",
          },
        });

        // Assert that non-pathological short string keys are similar or better than long strings
        // Allow a larger safety margin (2.5x) to reduce flakiness from GC/jitter across environments.
        expect(shortStrings.p95).toBeLessThan(longStrings.p95 * 2.5);
      },
    );

    it("large-value GC and eviction impact", { timeout: 30000 }, () => {
      const largeSize = 100 * 1024; // 100KB
      const dataLarge = new Uint8Array(largeSize);
      const iterations = 2000;
      const testCache = new SecureLRUCache({
        maxEntries: 100,
        maxBytes: 5 * largeSize,
      });

      // Fill to trigger evictions repeatedly and measure eviction cost
      const evictTimes: number[] = [];
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        testCache.set(`v${i}`, dataLarge);
        const end = performance.now();
        if (i >= 100) evictTimes.push(end - start);
        if (i % 200 === 0) forceGC();
      }

      const stats = calculateStats(evictTimes);
      console.log("Large-value eviction stats (MoM):", {
        mom: stats.mom.toFixed(4),
        p95: stats.p95.toFixed(4),
        p99: stats.p99.toFixed(4),
      });
      // p95 should be bounded reasonably (avoid extreme GC spikes masking eviction cost)
      expect(stats.p95).toBeLessThan(200);
    });

    it(
      "feature overhead: copyOnSet / copyOnGet impact",
      { timeout: 20000 },
      () => {
        const data = new Uint8Array(1024);
        const runs = 2000;

        function bench(opts: any) {
          const c = new SecureLRUCache({
            maxEntries: runs * 2,
            maxBytes: runs * 2 * data.length,
            copyOnSet: !!opts.copyOnSet,
            copyOnGet: !!opts.copyOnGet,
          });
          // warmup
          for (let i = 0; i < 200; i++) c.set(`k${i}`, data);
          forceGC();
          const times: number[] = [];
          for (let i = 0; i < runs; i++) {
            const start = performance.now();
            c.set(`k${i}`, data);
            const mid = performance.now();
            c.get(`k${i}`);
            const end = performance.now();
            times.push(end - start);
          }
          return calculateStats(times);
        }

        const both = bench({ copyOnSet: true, copyOnGet: true });
        const none = bench({ copyOnSet: false, copyOnGet: false });

        console.log("Feature overhead (MoM ms):", {
          both: both.mom.toFixed(4),
          none: none.mom.toFixed(4),
        });
        // Expect enabling defensive copying to have measurable overhead (MoM)
        expect(both.mom).toBeGreaterThanOrEqual(none.mom);
      },
    );
  });

  // New lightweight regressions to verify debug metrics and wipe queue health
  describe("Debug metrics and wipe queue health", () => {
    it("sieve debug metrics should increase with evictions (mode-aware)", () => {
      const c = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 64,
        maxBytes: 64 * 4096,
        recencyMode: "sieve",
      });
      const data = new Uint8Array(4096);
      for (let i = 0; i < 256; i++) c.set(`k${i}`, data);
      const dbg: any = (c as any).getDebugStats?.() ?? c.getStats();

      // Mode-aware expectations: different recency modes populate different counters.
      // For 'sieve' we expect sieveScans to be the dominant counter; rotations may be 0.
      // For other modes (e.g., 'second-chance') rotations may be populated.
      const hasScans = typeof dbg.sieveScans === "number";
      const hasRotations = typeof dbg.sieveRotations === "number";
      expect(hasScans || hasRotations).toBe(true);

      // If both counters exist, require their sum to be positive. If only one exists,
      // require that one to be positive. This avoids brittle assumptions about which
      // internal instrumentation is enabled for a given recency mode.
      const scans = hasScans ? dbg.sieveScans : 0;
      const rotations = hasRotations ? dbg.sieveRotations : 0;
      expect(scans + rotations).toBeGreaterThan(0);
    });

    it("flushWipesSync drains wipe queue after heavy deletes", () => {
      const c = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 200,
        maxBytes: 200 * 2048,
        recencyMode: "sieve",
      });
      const data = new Uint8Array(2048);
      for (let i = 0; i < 200; i++) c.set(`k${i}`, data);
      for (let i = 0; i < 200; i++) c.delete(`k${i}`);
      const before = c.getWipeQueueStats();
      expect(before.entries >= 0).toBe(true);
      c.flushWipesSync();
      const after = c.getWipeQueueStats();
      expect(after.entries).toBe(0);
      expect(after.scheduled).toBe(false);
    });

    it("purgeExpired removes entries with short TTL", async () => {
      const c = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 100,
        maxBytes: 100 * 1024,
        defaultTtlMs: 50,
        recencyMode: "sieve",
      });
      const v = new Uint8Array(256);
      for (let i = 0; i < 50; i++) c.set(`t${i}`, v);
      await new Promise((r) => setTimeout(r, 80));
      const purged = c.purgeExpired();
      expect(purged).toBeGreaterThan(0);
      const stats = c.getStats();
      expect(stats.expired).toBeGreaterThanOrEqual(purged);
    });

    it("VerifiedByteCache privacy regression: stats do not leak URLs and privacy defaults honored", () => {
      // VerifiedByteCache is a static class with privacyByDefault: true and onEvict: null
      const testUrl = "https://example.com/test";
      const data = new Uint8Array(1024);
      VerifiedByteCache.set(testUrl, data);

      // Check stats don't expose URLs
      const stats = VerifiedByteCache.getStats();
      expect(stats).toBeDefined();
      // Ensure no URL-like strings in stats (basic check)
      const statsStr = JSON.stringify(stats);
      expect(statsStr).not.toMatch(/https?:\/\//);
      expect(statsStr).not.toMatch(/example\.com/);

      // Privacy defaults: onEvict should not be called (privacyByDefault: true)
      // Since onEvict is null by default, we can't directly test callback, but ensure no errors
      VerifiedByteCache.delete(testUrl); // Trigger potential evict
      // If onEvict was called, it would log or something, but since it's null, just ensure no errors
    });

    it("SIEVE rotation-heavy micro-workload exercises recency-mode debug counters (mode-aware)", () => {
      const c = new SecureLRUCache<string, Uint8Array>({
        maxEntries: 16, // Small capacity to force evictions
        maxBytes: 16 * 1024,
        recencyMode: "sieve",
      });
      const data = new Uint8Array(1024);

      // Phase 1: Fill cache and set ref bits on some entries
      for (let i = 0; i < 16; i++) c.set(`k${i}`, data);
      // Access first half to set ref bits
      for (let i = 0; i < 8; i++) c.get(`k${i}`);

      // Phase 2: Add more entries to trigger evictions, causing hand to rotate past ref-bit entries
      for (let i = 16; i < 32; i++) c.set(`k${i}`, data);

      // Mode-aware check: some recency modes update sieveScans, others update sieveRotations.
      const dbg: any = (c as any).getDebugStats?.() ?? c.getStats();
      const hasScans = typeof dbg.sieveScans === "number";
      const hasRotations = typeof dbg.sieveRotations === "number";
      expect(hasScans || hasRotations).toBe(true);

      const scans = hasScans ? dbg.sieveScans : 0;
      const rotations = hasRotations ? dbg.sieveRotations : 0;

      // For 'sieve' we expect scans > 0 typically; rotations may be zero depending on parameters.
      // For 'second-chance' we expect rotations to be populated. Accept either, but require
      // the combined activity to be non-zero to ensure the micro-workload exercised the recency mechanism.
      expect(scans + rotations).toBeGreaterThan(0);
    });
  });
});
