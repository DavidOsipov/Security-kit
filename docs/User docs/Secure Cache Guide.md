# Secure Cache Guide

This guide helps developers integrate SecureLRU cache into their applications for secure, high-performance caching with OWASP ASVS L3 compliance.

## Quick Start

```javascript
import { SecureLRUCache } from "@david-osipov/security-kit";

// Basic usage with secure defaults
const cache = new SecureLRUCache({
  maxEntries: 1000,
  maxBytes: 10 * 1024 * 1024, // 10MB
  ttlMs: 60000, // 1 minute
});

// Set values (automatically copied for immutability)
await cache.set("user:123", { name: "Alice", role: "admin" });

// Get values (returns copies for security)
const user = await cache.get("user:123");

// Update existing entries
await cache.set("user:123", { ...user, lastLogin: Date.now() });

// Delete when needed
await cache.delete("user:123");
```

## Performance Characteristics

### Expected Performance

- **Small values (≤1KB)**: 200K-1.5M operations/sec
- **Medium values (8KB)**: 100K-800K operations/sec
- **Large values (64KB)**: 16K-200K operations/sec

### Security vs Performance Trade-off

SecureLRU prioritizes security over raw performance:

- **10-20x slower** than reference-returning caches for large values
- **Intentional design** for OWASP ASVS L3 compliance
- Values are **copied on set/get** to ensure immutability and prevent tampering

## Algorithm Selection

Choose the right eviction algorithm for your workload:

### SIEVE (Default - Recommended)

```javascript
const cache = new SecureLRUCache({
  recencyMode: "sieve",
  // Balanced performance across read/write operations
  // Best for: General-purpose caching, mixed workloads
});
```

### Second-Chance (Read-Optimized)

```javascript
const cache = new SecureLRUCache({
  recencyMode: "second-chance",
  // Optimized for read-heavy workloads
  // Best for: Lookup tables, configuration data, read-heavy APIs
});
```

### Segmented LRU (Predictable)

```javascript
const cache = new SecureLRUCache({
  recencyMode: "segmented",
  // Predictable scan costs, good for memory-constrained environments
  // Best for: Resource-limited environments, consistent performance needs
});
```

## Configuration Options

### Basic Configuration

```javascript
const cache = new SecureLRUCache({
  maxEntries: 1000, // Maximum number of cache entries
  maxBytes: 10 * 1024 * 1024, // Maximum total memory usage
  maxEntryBytes: 64 * 1024, // Maximum size per entry
  ttlMs: 300000, // Time-to-live in milliseconds (5 minutes)
  recencyMode: "sieve", // Eviction algorithm
});
```

### Performance Tuning

```javascript
const cache = new SecureLRUCache({
  // Algorithm-specific tuning
  segmentedEvictScan: 8, // SIEVE/segmented scan limit
  secondChanceMaxRotationsPerEvict: 8, // Second-chance rotation limit

  // Promote-on-get behavior
  promoteOnGet: "sampled", // 'always', 'sampled', or 'never'
  promoteOnGetSampleRate: 4, // Sample 1 in 4 gets for promotion

  // TTL and cleanup
  ttlResolutionMs: 500, // TTL check granularity
  ttlAutoPurge: true, // Automatic expired entry cleanup
});
```

### Security Configuration

```javascript
const cache = new SecureLRUCache({
  // Immutability controls (recommended: keep enabled for security)
  copyOnSet: true, // Copy values when storing (prevents external mutation)
  copyOnGet: true, // Copy values when retrieving (prevents cache pollution)

  // Secure wiping
  secureWipe: true, // Zero memory after deletion

  // Privacy controls
  onEvict: undefined, // Disable eviction callbacks to prevent data leaks
});
```

## Common Use Cases

### Web API Response Caching

```javascript
const apiCache = new SecureLRUCache({
  maxEntries: 5000,
  maxBytes: 50 * 1024 * 1024, // 50MB
  ttlMs: 900000, // 15 minutes
  recencyMode: "second-chance", // Read-heavy optimization
});

// Cache API responses
async function fetchUserData(userId) {
  const cacheKey = `user:${userId}`;
  let userData = await apiCache.get(cacheKey);

  if (!userData) {
    userData = await api.getUser(userId);
    await apiCache.set(cacheKey, userData);
  }

  return userData;
}
```

### Session Storage

```javascript
const sessionCache = new SecureLRUCache({
  maxEntries: 10000,
  maxBytes: 100 * 1024 * 1024, // 100MB
  ttlMs: 1800000, // 30 minutes
  recencyMode: "sieve", // Balanced read/write
  secureWipe: true, // Important for session data
});

// Store session data securely
async function storeSession(sessionId, sessionData) {
  await sessionCache.set(sessionId, {
    ...sessionData,
    lastAccess: Date.now(),
  });
}
```

### Computed Result Caching

```javascript
const computeCache = new SecureLRUCache({
  maxEntries: 1000,
  maxBytes: 20 * 1024 * 1024, // 20MB
  ttlMs: 3600000, // 1 hour
  recencyMode: "segmented", // Predictable for resource planning
  promoteOnGet: "never", // Don't promote cached computations
});

// Cache expensive computations
async function getProcessedData(inputHash) {
  let result = await computeCache.get(inputHash);

  if (!result) {
    result = await expensiveComputation(inputHash);
    await computeCache.set(inputHash, result);
  }

  return result;
}
```

## Best Practices

### Memory Management

- **Size appropriately**: Set `maxBytes` based on available memory
- **Monitor usage**: Use `cache.getStats()` to track memory consumption
- **Large values**: Consider compression for values >8KB
- **Capacity planning**: Account for copying overhead in memory calculations

### Security Considerations

- **Keep copying enabled**: Disable `copyOnSet`/`copyOnGet` only in trusted, performance-critical scenarios
- **Secure sensitive data**: Enable `secureWipe` for sensitive information
- **Avoid eviction callbacks**: Don't use `onEvict` with sensitive data to prevent leaks
- **TTL for security**: Use appropriate TTL values for time-sensitive data

### Performance Optimization

- **Algorithm selection**: Use benchmarks to validate algorithm choice for your workload
- **Batch operations**: Group multiple cache operations when possible
- **Async operations**: Use `setAsync` for large values to avoid blocking
- **Monitor metrics**: Track hit rates and operation latencies

## Monitoring and Debugging

### Basic Statistics

```javascript
const stats = cache.getStats();
console.log("Cache stats:", {
  entries: stats.entries,
  bytes: stats.bytes,
  hitRate: stats.hits / (stats.hits + stats.misses),
});
```

### Debug Information

```javascript
const debug = cache.getDebugStats();
console.log("Algorithm performance:", {
  evictions: debug.evictions,
  sieveScans: debug.sieveScans, // SIEVE-specific
  sieveRotations: debug.sieveRotations, // Second-chance specific
});
```

### Wipe Queue Monitoring

```javascript
const wipeStats = cache.getWipeQueueStats();
if (wipeStats.pending > 1000) {
  console.warn("High wipe queue backlog:", wipeStats);
  await cache.flushWipes(); // Manual flush if needed
}
```

## Troubleshooting

### Performance Issues

- **Slow operations**: Check if values are unexpectedly large
- **Memory pressure**: Reduce `maxBytes` or `maxEntries`
- **High miss rate**: Increase cache size or reduce TTL

### Capacity Errors

- **Entry too large**: Increase `maxEntryBytes` or reduce value size
- **Cache full**: Increase `maxBytes` or `maxEntries`
- **Wipe queue full**: Enable `ttlAutoPurge` or call `flushWipes()` manually

### Algorithm Tuning

- **Read-heavy**: Switch to `recencyMode: 'second-chance'`
- **Write-heavy**: Use `recencyMode: 'sieve'` with appropriate `segmentedEvictScan`
- **Memory-constrained**: Use `recencyMode: 'segmented'` for predictable costs

## Integration Examples

### Express.js Middleware

```javascript
import express from "express";
import { SecureLRUCache } from "@david-osipov/security-kit";

const cache = new SecureLRUCache({
  maxEntries: 10000,
  ttlMs: 600000, // 10 minutes
});

function cacheMiddleware(ttl = 600000) {
  return async (req, res, next) => {
    const key = `${req.method}:${req.originalUrl}`;
    const cached = await cache.get(key);

    if (cached) {
      return res.json(cached);
    }

    // Override res.json to cache response
    const originalJson = res.json;
    res.json = function (data) {
      cache.set(key, data);
      return originalJson.call(this, data);
    };

    next();
  };
}

app.get("/api/users/:id", cacheMiddleware(), getUserHandler);
```

### Next.js API Routes

```javascript
import { SecureLRUCache } from "@david-osipov/security-kit";

const cache = new SecureLRUCache({
  maxEntries: 5000,
  ttlMs: 300000, // 5 minutes
});

export default async function handler(req, res) {
  const cacheKey = `api:${req.url}`;

  // Try cache first
  const cached = await cache.get(cacheKey);
  if (cached) {
    return res.status(200).json(cached);
  }

  // Compute result
  const result = await fetchData(req.query);

  // Cache and return
  await cache.set(cacheKey, result);
  res.status(200).json(result);
}
```

This guide provides the essential information developers need to effectively use SecureLRU in their applications while maintaining security best practices.

- Wipe caps: `maxWipeQueueBytes`, `maxWipeQueueEntries` bound deferred wipes and fail over to sync wiping.
- Callbacks: `onEvict` runs asynchronously after mutation to prevent reentrancy hazards.
- Privacy by default: `evictCallbackExposeUrl` defaults to `false`. Provide `onEvictKeyMapper(url)=>string` to hash or sanitize keys for telemetry.

## Time and TTL

- `ttlResolutionMs` controls batching. Coarser ticks (e.g., 500–1000ms) improve throughput but increase expiry jitter up to that value.
- `ttlAutopurge: true` periodically removes expired entries out-of-band; keep it on for long-lived processes.

## Tuning knobs

- `promoteOnGet: 'always' | 'sampled'` and `promoteOnGetSampleRate` (1-in-N via modulo; any positive integer)
- `recencyMode: 'lru' | 'segmented' | 'second-chance' | 'sieve'`
- `segmentedEvictScan`, `segmentRotateEveryOps`
- `secondChanceMaxRotationsPerEvict`
- Wipes: `wipeStrategy`, `maxDeferredWipesPerFlush`, `deferredWipeScheduler`, `deferredWipeTimeoutMs`
- Deferred wipe caps: `maxWipeQueueBytes`, `maxWipeQueueEntries`
- Telemetry/privacy: `evictCallbackExposeUrl`, `onEvictKeyMapper`
- Time: `clock` override for monotonic time if desired

## VerifiedByteCache

A preconfigured singleton optimized for byte payloads. It forces `promoteOnGet: 'always'` for strict MRU semantics. Use when you just need a safe, fast bytes cache without custom tuning.

import { VerifiedByteCache } from '@david-osipov/security-kit/src/secure-cache';
const bytes = await VerifiedByteCache.get(url);

// Admin helpers
const exists = VerifiedByteCache.has(url); // no promotion
const peeked = VerifiedByteCache.peek(url); // copy + optional freeze
const purged = VerifiedByteCache.purgeExpired();
await VerifiedByteCache.flushWipes(); // or .flushWipesSync()
const wipeStats = VerifiedByteCache.getWipeQueueStats();

## Recipes

1. Read-mostly API cache

- Profile: `read-heavy-lru-coarse`
- Key opts: `promoteOnGet: 'sampled', promoteOnGetSampleRate: 8, ttlResolutionMs: 1000`

2. Mixed read/write with frequent updates

- Profile: `throughput-segmented-aggressive`
- Key opts: `recencyMode: 'segmented', segmentedEvictScan: 8, segmentRotateEveryOps: 5000`

3. Pointer-churn-sensitive service

- Profile: `experimental-sieve`
- Key opts: `recencyMode: 'sieve', segmentedEvictScan: 6` (bounds work while hand advances)

4. Developer local runs

- Prefer `balanced` with smaller limits and `ttlAutopurge: false` for simpler tracing. Flip to `true` before shipping.

## Diagnostics

Use `getDebugStats()` to surface policy-specific counters such as `sieveScans` and `sieveRotations`, plus hits/misses/evictions. Emit them on a health endpoint or log periodically.

### Benchmark methodology (important)

To avoid artifacts and measure fairly:

- Do not perform `set()` inside the timed section of `GET`, `UPDATE`, or `DELETE` tasks. Pre-populate the task-specific caches with keys using the same prefixes (e.g., `g*`, `u*`, `d*`) and then time only the target operation.
- Keep performance runs quiet by setting `QUIET_SECURELRU_WARN=1` to suppress coalesced wipe warnings during heavy churn. Production logging remains redacted and coalesced by default.
- Maintain steady occupancy: for `DELETE`, re-insert the key after timing.

This prevents measuring unintended work (e.g., a `GET` that first does a `set`) which can vastly distort throughput numbers.

## Do’s and don’ts

- Do cap `maxEntryBytes` to block pathological inputs.
- Do keep `rejectSharedBuffers: true` unless you fully control producers.
- Do choose a coarse `ttlResolutionMs` in prod to reduce overhead.
- Do expect `onEvict` to be asynchronous; avoid re-entrant mutations in callbacks.
- Do sanitize or hash keys passed to telemetry by supplying `onEvictKeyMapper` or set `evictCallbackExposeUrl: false`.
- Do prefer the default `copyOnSet: true` and `copyOnGet: true` for immutability in shared libraries.
- Don’t return mutable references unless you disable copying knowingly.
- Don’t rely on exact millisecond expiry—jitter equals `ttlResolutionMs`.
- Don’t rely on `Object.freeze` to make typed array contents immutable—only the wrapper is frozen; the bytes remain mutable per JS semantics.

## Recency modes and tuning quick guide

- Read-mostly: `promoteOnGet: 'sampled'` with `promoteOnGetSampleRate: 4..8`, `recencyMode: 'segmented'` or `'second-chance'` with `segmentedEvictScan: 32..64`. For second-chance, `secondChanceMaxRotationsPerEvict: 2..4` balances work.
- Mixed workloads: `recencyMode: 'segmented'`, `segmentedEvictScan: 8..32`, `segmentRotateEveryOps: 5_000..10_000`.
- Pointer-churn sensitive: `recencyMode: 'sieve'` with moderate `segmentedEvictScan` (6..16). Validate with `_debug` counters to ensure hand advances without excessive scans.

Security posture is preserved in all modes; prefer coarser `ttlResolutionMs` to reduce per-op overhead while accepting expiry jitter.

## Third-party cache benchmark notes

- `js-sieve`: highly optimized SIEVE cache used in benchmarks for comparison. It does not support `DELETE` in our harness and does not implement the OWASP-aligned safeguards (secure wiping, TTL batching, privacy controls). Use only as a performance reference; for security-critical workloads, prefer `SecureLRUCache` variants.

## Running benchmarks

Quiet compare run:

```sh
BENCH_RUNS=1 npm run -s bench:compare
```

Environment knobs for sweeps:

```sh
# Examples
SEG_SCAN=64 SC_MAX_ROT=2 BENCH_RUNS=1 npm run -s bench:compare
PROFILE=throughput-segmented-aggressive BENCH_RUNS=1 npm run -s bench:compare
```

Interpreting `_debug`:

- `sieveScans`, `sieveRotations`: higher counts indicate more internal scanning/rotations; correlate with throughput to pick budgets.
- `evictions`, `expired`: workload pressure and TTL behavior; ensure caps and TTL settings fit your environment.

## Troubleshooting

- Entries not expiring? Ensure the process clock advances and `ttlAutopurge` is enabled or a get/set path runs.
- Throughput regressions? Try `segmented` or sampled promotion; coarsen `ttlResolutionMs`.
- Unexpected evictions? Check size limits and onEvict events; set `maxBytes` conservatively.
- OOM or memory growth under heavy churn? Lower `maxDeferredWipesPerFlush`, set `maxWipeQueueBytes` / `maxWipeQueueEntries`, or switch to `wipeStrategy: 'sync'` for secret-heavy workloads.
- TTL skew on servers? Provide a monotonic `clock: () => performance.now()` and consider coarser `ttlResolutionMs`.

## API surface (selected)

new SecureLRUCache<K, V>(options)

- options.maxEntries, maxBytes, maxEntryBytes
- options.recencyMode, promoteOnGet, promoteOnGetSampleRate
- options.ttlAutopurge, ttlResolutionMs
- options.wipeStrategy, maxDeferredWipesPerFlush, deferredWipeScheduler, deferredWipeTimeoutMs
- options.maxWipeQueueBytes, maxWipeQueueEntries
- options.evictCallbackExposeUrl, onEvictKeyMapper
- options.clock
- options.segmentedEvictScan, segmentRotateEveryOps, secondChanceMaxRotationsPerEvict

cache.set(key, value, { ttlMs? })
cache.get(key)
cache.delete(key)
cache.clear()
cache.getDebugStats()
cache.has(key)
cache.peek(key)
cache.purgeExpired()
cache.flushWipes(), cache.flushWipesSync(), cache.getWipeQueueStats()

## Notes

- All profiles and options are tree-shakable. Import only what you use.
- The cache avoids unbounded sync work; eviction scans are windowed and hand-advanced.
- Zeroization is best-effort in JS. Engines may keep ephemeral copies; prefer minimizing copies, using `wipeStrategy: 'sync'` for secrets, and zeroing on the consumer side when possible.
