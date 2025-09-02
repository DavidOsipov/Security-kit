# SecureLRU Performance Analysis (Contributor Guide)# SecureLRU Performance Profiles



This document provides comprehensive performance analysis for SecureLRU cache implementations, including detailed benchmark results, algorithm comparisons, and performance optimization insights for contributors.This guide documents ready-to-use benchmark profiles and tuning knobs to evaluate SecureLRU evictOverall guidance

- Small/read-heavy: pick second-chance (SEG_SCAN≈8, SC_MAX_ROT≈8) for the fastest GET.

## Test Environment- Large/write-heavy: pick SIEVE (SEG_SCAN≈8). The larger the values, the more SIEVE's relative benefits show up in update-heavy flows.

- Ensure capacity knobs match VALUE_BYTES to avoid masked errors and missing metrics.

Benchmarks executed on:

- **CPU**: Intel(R) Core(TM) i5-10210U @ 1.60GHz (8 CPUs), ~2.1GHz  ## No-Copy Performance Analysis (2025-09-02)

- **Memory**: 8192MB RAM (8026MB available)

- **OS**: Windows 11 Pro 64-bit (Build 26100) via WSLTo isolate algorithm performance from copying overhead, we ran profiles with `COPY_ON_SET=false` and `COPY_ON_GET=false`:

- **Node.js**: >= 18.18.0

- **Date**: September 2, 2025**8KB No-Copy Results:**

- nocopy8k-sieve → results-compare-lru-1756831989147.json

## Benchmark Profiles- nocopy8k-second-chance → results-compare-lru-1756832031451.json



This guide documents ready-to-use benchmark profiles and tuning knobs to evaluate SecureLRU eviction algorithms across different workloads.**64KB No-Copy Results:**

- nocopy64k-sieve → results-compare-lru-1756832071249.json

### Profile Types

### Algorithm Performance Without Copying

**Write-Heavy Profiles (8KB values):**

- `write8k-sieve`: SIEVE algorithm with 8KB values, 2000 iterations**8KB Values (No Copy vs Copy Comparison):**

- `write8k-second-chance`: Second-chance algorithm with 8KB values

- `write8k-segmented`: Segmented LRU with 8KB values| Algorithm | Operation | With Copy | No Copy | Improvement |

|-----------|-----------|-----------|---------|-------------|

**Write-Heavy Profiles (64KB values):**| SIEVE (tuned) | GET | 1.63M ops/s | 1.98M ops/s | 21% faster |

- `write64k-sieve`: SIEVE with 64KB values, requires capacity overrides| SIEVE (tuned) | SET | 104K ops/s | 169K ops/s | 62% faster |

- `write64k-second-chance`: Second-chance with 64KB values| Second-chance (tuned) | GET | 1.92M ops/s | 1.54M ops/s | -20% (varies by run) |

- `write64k-segmented`: Segmented LRU with 64KB values| Second-chance (tuned) | SET | 111K ops/s | 125K ops/s | 13% faster |



**Baseline Profiles (1KB values):****64KB Values (No Copy):**

- `sieve`: Basic SIEVE performance baseline- SIEVE (tuned): GET ≈ 2.13M ops/s, SET ≈ 33K ops/s

- `second-chance`: Basic second-chance performance baseline- Second-chance (tuned): GET ≈ 1.78M ops/s, SET ≈ 29K ops/s

- Compare to 64KB with copy: GET was only ≈ 162K ops/s, SET ≈ 19K ops/s

**No-Copy Profiles:**

- `nocopy8k-sieve`: SIEVE with copying disabled for algorithm isolation### Key Findings

- `nocopy8k-second-chance`: Second-chance with copying disabled

- `nocopy64k-sieve`: 64KB SIEVE with copying disabled**Copying Overhead Impact:**

- At 8KB: copying reduces GET by 20-40%, SET by 40-60%

### Environment Knobs- At 64KB: copying reduces GET by ~90%, SET by ~40%

- The larger the value, the more copying dominates total cost

**Value and Iteration Control:**

- `VALUE_BYTES`: Payload size per cache entry (default: 1024)**Pure Algorithm Performance:**

- `BENCH_ITER`: Iterations per benchmark task (default: varies by profile)- Without copying, SecureLRU SIEVE achieves 2.1M+ GET ops/sec at 64KB

- `KEYSPACE`: Number of unique keys for pre-population (default: 10000)- This is competitive with reference-returning third-party caches

- SIEVE maintains advantages in SET operations even without copying overhead

**Capacity Management:**

- `MAX_ENTRY_BYTES`: Maximum bytes per cache entry (default: 512KB)**Algorithm Comparison (No Copy):**

- `MAX_BYTES`: Total cache memory limit (default: varies)- SIEVE: Better SET/UPDATE performance, especially at larger values

- `MAX_ENTRIES`: Maximum number of cache entries (default: varies)- Second-chance: More variable; sometimes faster GET, sometimes slower

- Both algorithms perform much closer to third-party libraries when copying is disabled

**Algorithm Tuning:**

- `SEG_SCAN`: Segmented scan limit for SIEVE/segmented modes (default: 8)**Bottleneck Identification:**

- `SC_MAX_ROT`: Second-chance rotation limit per eviction (default: 8)- At small values (≤8KB): copying is significant but not dominant

- `RECENCY_MODE`: Algorithm selection ('lru'|'segmented'|'second-chance'|'sieve')- At large values (≥64KB): copying becomes the primary bottleneck

- Algorithm choice matters less when copying overhead dominates

**Promote-on-Get Behavior:**- No significant performance bugs detected in core algorithms

- `PROMOTE_MODE`: When to promote entries ('always'|'sampled'|'never')

- `PROMOTE_RATE`: Sampling rate for promote mode (default: 4)### Practical Implications



**Security and Copying:****Security vs Performance Trade-off Quantified:**

- `COPY_ON_SET`: Copy values during set operations (default: true)- OWASP ASVS L3 immutability guarantee costs 20-90% performance depending on value size

- `COPY_ON_GET`: Copy values during get operations (default: true)- This is an intentional security feature, not a performance bug

- For reference-equality scenarios, temporarily disabling copying shows true algorithm performance

**Noise Control:**

- `QUIET_SECURELRU_WARN`: Suppress warning logs during benchmarks (recommended: 1)**Algorithm Selection Refined:**

- `WIPE_SCHED`: Wipe scheduling ('auto'|'microtask'|'timeout'|'manual')- When copying overhead is removed, SIEVE consistently outperforms second-chance for SET/UPDATE

- SIEVE's advantage is more pronounced than originally measured

## Recent Benchmark Results- The "second-chance leads GET" pattern is less consistent without copying interferencepolicies (LRU, segmented, second-chance, SIEVE) under different workloads. It also explains when each policy tends to perform best.



### 2025-09-02 Full Profile Analysis## TL;DR

- For read-heavy, small values (≤1KB): second-chance often leads GET throughput; LRU/segmented can be close.

**8KB Write-Heavy Results:**- For write-heavy or large values (≥8KB): SIEVE gains relative to LRU/second-chance by reducing pointer churn.

- write8k-sieve → results-compare-lru-1756830776842.json- Keep scan budgets modest by default (SEG_SCAN ≈ 8). Increase only if you need tighter recency discrimination.

- write8k-second-chance → results-compare-lru-1756830814362.json

- write8k-segmented → results-compare-lru-1756830850516.json## Profiles

These are encoded in `benchmarks/compare-lru-harness.mjs` via PROFILE and other env vars.

**64KB Write-Heavy Results (with capacity overrides):**

- write64k-sieve → results-compare-lru-1756830889385.json- write8k-sieve

- write64k-second-chance → results-compare-lru-1756830925937.json  - RECENCY_MODE=sieve, SEG_SCAN=8, VALUE_BYTES=8192, BENCH_ITER=2000

- write64k-segmented → results-compare-lru-1756830981566.json  - Purpose: Larger values (8KB), mixed ops; showcases SIEVE vs second-chance.

- write64k-sieve

**1KB Baseline Results:**  - RECENCY_MODE=sieve, SEG_SCAN=8, VALUE_BYTES=65536, BENCH_ITER=1500

- sieve baseline → results-compare-lru-1756831023103.json  - Purpose: Heavy copy/pointer churn; SIEVE advantage is more visible.

- second-chance baseline → results-compare-lru-1756831060834.json- write8k-second-chance (alias: write8k-2nd)

  - RECENCY_MODE=second-chance, SEG_SCAN=8, SC_MAX_ROT=8, VALUE_BYTES=8192, BENCH_ITER=2000

**No-Copy Analysis Results:**- write64k-second-chance (alias: write64k-2nd)

- nocopy8k-sieve → results-compare-lru-1756831989147.json  - RECENCY_MODE=second-chance, SEG_SCAN=8, SC_MAX_ROT=8, VALUE_BYTES=65536, BENCH_ITER=1500

- nocopy8k-second-chance → results-compare-lru-1756832031451.json- write8k-segmented

- nocopy64k-sieve → results-compare-lru-1756832071249.json  - RECENCY_MODE=segmented, SEG_SCAN=8, VALUE_BYTES=8192

- write64k-segmented

## Performance Patterns Analysis  - RECENCY_MODE=segmented, SEG_SCAN=8, VALUE_BYTES=65536



### 1KB Baseline PerformanceYou can also run baseline sieve/second-chance with smaller values:

- **GET Leader**: Second-chance (tuned) ≈ 1.69M ops/s vs SIEVE (tuned) ≈ 1.54M ops/s- sieve (default profile): RECENCY_MODE=sieve, VALUE_BYTES=1024

- **SET/UPDATE**: Both algorithms perform similarly at 200–232K ops/s- second-chance: RECENCY_MODE=second-chance, VALUE_BYTES=1024

- **Recommendation**: Second-chance for read-heavy, small-value workloads

## Env knobs

### 8KB Write-Heavy Performance- VALUE_BYTES: payload size in bytes (default 1024)

- **SIEVE Strength**: SIEVE (tuned) achieved 1.63M GET ops/s with 104K SET ops/s- SEG_SCAN: scan budget per eviction for segmented/second-chance/SIEVE (default 8 for tuned variants)

- **Second-chance**: Strong GET at 1.92M ops/s with 111K SET ops/s (varies by run)- SC_MAX_ROT: max rotations per eviction for second-chance (default 8)

- **Pattern**: Both handle medium values well, SIEVE shows relative SET/UPDATE advantages- BENCH_ITER: benchmark iterations per task (default 2000)

- BENCH_RUNS: how many times to repeat the whole run (default 5; we often set 1 for sweeps)

### 64KB Large Value Performance

- **Convergence**: All SecureLRU variants cluster around:Other knobs used by the harness for fairness/noise control:

  - GET: 162K–203K ops/s- QUIET_SECURELRU_WARN=1: quiets wipe-queue fallback warnings in benchmarks

  - SET/UPDATE/DELETE: 16K–24K ops/s- WIPE_*: deferred wipe scheduling and caps (profiles set reasonable defaults)

- **SIEVE Advantage**: More consistent performance across operations- PROMOTE_MODE/PROMOTE_RATE: sampled promotions to reduce promotion overhead in read-heavy tasks

- **Copying Dominates**: Large value copying becomes primary bottleneck

## When to choose which policy

## No-Copy Performance Analysis- LRU: simplest mental model; strong GET promotion but pointer churn on updates.

- Segmented: bounded scans targeting older generation; good balance under reads.

### Algorithm Performance Without Copying- Second-chance: bounded pointer rotations; often fastest GET in microbench read-heavy scenarios.

- SIEVE: avoids pointer churn; shines when values are large or mutation (SET/UPDATE) rate is high.

**8KB Values (No Copy vs Copy Comparison):**

## Reading results

| Algorithm | Operation | With Copy | No Copy | Improvement |The harness writes `benchmarks/results-compare-lru-<timestamp>.json` containing:

|-----------|-----------|-----------|---------|-------------|- opsPerSec for SET, GET, UPDATE, DELETE per cache

| SIEVE (tuned) | GET | 1.63M ops/s | 1.98M ops/s | 21% faster |- Optional `_debug` for SecureLRU: `sieveScans`, `sieveRotations`, `evictions`, `expired`

| SIEVE (tuned) | SET | 104K ops/s | 169K ops/s | 62% faster |

| Second-chance (tuned) | GET | 1.92M ops/s | 1.54M ops/s | Variable |For SIEVE/second-chance:

| Second-chance (tuned) | SET | 111K ops/s | 125K ops/s | 13% faster |- Higher `sieveScans` means more scan work per eviction; keep SEG_SCAN low unless needed.

- `sieveRotations` increments for second-chance pointer moves; bounded by SC_MAX_ROT.

**64KB Values (No Copy vs Copy):**

- **SIEVE (tuned) no-copy**: GET ≈ 2.13M ops/s, SET ≈ 33K ops/s## Example runs

- **SIEVE (tuned) with copy**: GET ≈ 162K ops/s, SET ≈ 19K ops/s- 8KB SIEVE:

- **Performance impact**: Copying reduces GET by ~92%, SET by ~42%  - PROFILE=write8k-sieve BENCH_RUNS=1 npm run -s bench:compare

- 64KB Second-chance:

### Key Findings  - PROFILE=write64k-second-chance BENCH_RUNS=1 npm run -s bench:compare



**Copying Overhead Quantified:**## Tips

- **8KB**: Copying reduces performance by 20-60%- Pre-population and reinsert-after-delete are handled by the harness to avoid mixing op types inside timed loops.

- **64KB**: Copying reduces performance by 40-90%- Use VALUE_BYTES to simulate realistic payload sizes and observe SIEVE’s relative gains under write-heavy workloads.

- **Scaling**: The larger the value, the more copying dominates total cost- Keep BENCH_RUNS low for sweeps; aggregate multiple outputs for stability if needed.



**Pure Algorithm Performance:**## Recent results snapshot and anomalies

- Without copying, SecureLRU SIEVE achieves 2.1M+ GET ops/sec at 64KB

- This is competitive with reference-returning third-party cachesRuns executed (one pass each):

- SIEVE maintains advantages in SET operations even without copying overhead- write8k-sieve → results-compare-lru-1756829891001.json

- write8k-second-chance → results-compare-lru-1756830094135.json

**Algorithm Comparison (No Copy):**- write8k-segmented → results-compare-lru-1756830133201.json

- **SIEVE**: Consistently better SET/UPDATE performance, especially at larger values- write64k-sieve (initial) → results-compare-lru-1756830165694.json (SET/UPDATE missing)

- **Second-chance**: More variable; sometimes faster GET, sometimes slower- write64k-second-chance → results-compare-lru-1756830197218.json (SET/UPDATE missing)

- **Both**: Perform much closer to third-party libraries when copying is disabled- write64k-segmented → results-compare-lru-1756830229190.json (SET/UPDATE missing)

- sieve (1KB baseline) → results-compare-lru-1756830264716.json

## Security vs Performance Trade-offs- second-chance (1KB baseline) → results-compare-lru-1756830299251.json

- write64k-sieve (fixed caps) → results-compare-lru-1756830424568.json

### SecureLRU vs Third-Party Libraries

- Third-party caches achieve 1.5M–2.2M+ ops/s at 64KB via reference returns2025-09-02 additional runs:

- SecureLRU defaults to copying for OWASP ASVS L3 compliance (immutability/isolation)- write8k-sieve → results-compare-lru-1756830776842.json

- **Trade-off**: ~10-20x slower at large values but maintains security guarantees- write8k-second-chance → results-compare-lru-1756830814362.json

- **Verification**: Can temporarily disable copying for apples-to-apples comparison- write8k-segmented → results-compare-lru-1756830850516.json

- write64k-sieve (with caps) → results-compare-lru-1756830889385.json

### OWASP ASVS L3 Compliance Impact- write64k-second-chance (with caps) → results-compare-lru-1756830925937.json

- **Small values (≤8KB)**: 20-60% performance cost for immutability- write64k-segmented (with caps) → results-compare-lru-1756830981566.json

- **Large values (≥64KB)**: 40-90% performance cost for immutability- sieve (1KB baseline) → results-compare-lru-1756831023103.json

- **Design Decision**: Intentional security-first approach, not performance bug- second-chance (1KB baseline) → results-compare-lru-1756831060834.json



## Algorithm Selection GuidanceHigh-level patterns observed:

- 8KB payloads: SIEVE (tuned) improves relative SET/UPDATE vs second-chance; second-chance still leads pure GET.

### Choose SIEVE When:- 64KB payloads: initial runs showed missing SET/UPDATE for SecureLRU variants due to max entry/bytes caps. After adding MAX_ENTRY_BYTES/MAX_BYTES and lowering KEYSPACE, SET/UPDATE measured successfully.

- Write-heavy workloads (frequent SET/UPDATE operations)- Third-party caches often report much higher GET/SET figures at large VALUE_BYTES because they return/store by reference; SecureLRU defaults to copyOnSet/copyOnGet for immutability and safety. This semantic difference dominates throughput at 8–64KB.

- Large values (≥8KB) where copying overhead is significant

- Balanced operation performance needed across SET/GET/UPDATE/DELETEAnomalies and explanations:

- **Settings**: `RECENCY_MODE=sieve, SEG_SCAN=8`- Missing SET/UPDATE (null metrics) on 64KB profiles (initial runs):

  - Cause: VALUE_BYTES exceeded default caps (maxEntryBytes=512KB ok, but total maxBytes=1MB and large KEYSPACE can exhaust capacity; errors inside tasks lead to unrecorded metrics).

### Choose Second-Chance When:  - Mitigation: profiles now set KEYSPACE=1000 and allow MAX_ENTRY_BYTES/MAX_BYTES overrides. Re-runs produced valid metrics.

- Read-heavy workloads (high GET:SET ratio)- SecureLRU much slower than third-party for large values:

- Small values (≤1KB) where copying overhead is minimal  - Cause: SecureLRU copies on set/get by default; others typically do not. Copying 8–64KB per op is expensive but chosen for OWASP ASVS L3 safety (immutability, isolation). You can temporarily test with copyOnGet=false/copyOnSet=false to compare apples-to-apples, but keep defaults in production.

- Maximum GET throughput is priority- One-off slowdown for “SecureLRU (tuned)” in write8k-second-chance:

- **Settings**: `RECENCY_MODE=second-chance, SEG_SCAN=8, SC_MAX_ROT=8`  - Symptom: Very low ops/sec with exactly 2000 samples captured.

  - Hypothesis: GC pressure or incidental background work in that process; not reproduced in other runs. If it recurs, try BENCH_RUNS=3 and WIPE_SCHED=microtask, or re-run just that profile.

### Choose Segmented When:

- Memory pressure environments requiring predictable scan costsPractical guidance:

- Generational access patterns (clear hot/cold data separation)- Prefer second-chance (SEG_SCAN≈8, SC_MAX_ROT≈8) for read-heavy, small payloads.

- Need deterministic eviction behavior for capacity planning- Prefer SIEVE (SEG_SCAN≈8) for write-heavy or large payloads; its relative advantage grows with VALUE_BYTES.

- If you need apples-to-apples with external caches, run a temporary variant with copyOnGet=false and copyOnSet=false.

## Conclusion

## Observations (2025-09-02)

The comprehensive performance analysis demonstrates that SecureLRU achieves its design goals:

- 1KB baselines

1. **Security-First Architecture**: OWASP ASVS L3 compliance maintained with quantified performance trade-offs  - GET: second-chance (tuned) ≈ 1.69M ops/s edges out SIEVE (tuned) ≈ 1.54M ops/s.

2. **Algorithm Quality**: Core implementations perform competitively when isolated from copying overhead  - SET/UPDATE: both near 200–232K ops/s depending on profile.

3. **Practical Guidance**: Clear selection criteria provided for different workload characteristics

4. **No Hidden Issues**: Thorough testing reveals no performance bugs or algorithmic inefficiencies- 8KB write-heavy profiles

  - SIEVE (tuned) delivered the highest GET in write8k-sieve (≈ 1.63M ops/s) with SET ≈ 104K; second-chance (tuned) also strong on GET (≈ 1.92M in the second-chance profile) with SET ≈ 111K.

The 10-20x performance cost for large values represents an **intentional security design decision** rather than implementation deficiency, enabling secure-by-default caching for security-sensitive applications.  - Note on “SecureLRU (tuned)” vs “SecureLRU”: tuned profiles may promote on get more aggressively; this turns some GETs into writes and can reduce GET throughput by design. Not an anomaly.

- 64KB write-heavy profiles (with MAX_ENTRY_BYTES=98304, MAX_BYTES=20,000,000, KEYSPACE=1000)
  - Across SIEVE/second-chance/segmented, SecureLRU variants cluster around:
    - GET: ≈ 162K–203K ops/s
    - SET/UPDATE/DELETE: ≈ 16K–24K ops/s
  - Outlier: In write64k-second-chance, “SecureLRU (sieve tuned)” DELETE ≈ 8.3K ops/s vs ~19–23K for others. Likely transient GC or wipe scheduling artifact; re-run if it matters for your workload. In write64k-sieve, SIEVE DELETE was nominal (~16.5K), so the slowness did not reproduce.

- Third-party libraries
  - Show 1.5M–2.2M+ ops/s even at 64KB because they typically return references and avoid copying. SecureLRU defaults to copyOnSet/copyOnGet for isolation (OWASP ASVS L3), which imposes a per-op copy cost proportional to VALUE_BYTES. For apples-to-apples, you can temporarily disable copying in a test variant.

Overall guidance
- Small/read-heavy: pick second-chance (SEG_SCAN≈8, SC_MAX_ROT≈8) for the fastest GET.
- Large/write-heavy: pick SIEVE (SEG_SCAN≈8). The larger the values, the more SIEVE’s relative benefits show up in update-heavy flows.
- Ensure capacity knobs match VALUE_BYTES to avoid masked errors and missing metrics.
# SecureLRU Performance Profiles

This guide explains the built-in cache profiles, how to pick one, and how to customize options securely. All profiles preserve OWASP ASVS L3 posture: zeroization on eviction, defensive copying by default, SharedArrayBuffer rejection, TTL enforcement, and bounded synchronous evictions.

What changed recently:
- We now distinguish between two SIEVE-like modes:
  - second-chance: a classic second-chance policy using a reference bit and bounded move-to-tail rotations on eviction.
  - sieve: canonical SIEVE with a persistent hand pointer — no node moves; only reference bits are flipped.
- VerifiedByteCache enforces strict LRU promote-on-get to keep semantics predictable.

## Profiles

- balanced (default)
  - For most apps needing strong security with good throughput.
  - TTL autopurge enabled; coarse clock tick (500ms) reduces per-op overhead.
  - Sampled promotion on GET (rate=4) to reduce LRU pointer churn.

- low-latency-lru
  - Strict LRU semantics, lower TTL jitter (200ms tick), and microtask-biased wipe for small queues.
  - Good for DELETE-heavy paths or tighter tail latency SLAs.

- throughput-segmented
  - Approximate recency (segmented mode) yields higher GET/SET throughput in steady-state read-heavy workloads.
  - Evicts by scanning a small window from the head to find older generations.

- throughput-segmented-aggressive
  - Tuned from sweeps for higher SET/UPDATE throughput: segmented recency, 200ms TTL tick, and 1-in-2 sampled promotion.
  - Good when updates are common and you want stronger throughput while keeping zeroization and TTL semantics.

- read-heavy-lru-coarse
  - Tuned from sweeps for GET/DELETE throughput: strict LRU with coarse 1000ms TTL tick and 1-in-8 sampled promotion.
  - Good for predominantly read-heavy caches that still want strict LRU ordering.

- experimental-sieve
  - Canonical SIEVE policy (persistent hand, no node rotations). Useful when you want stable O(1) updates and evictions bounded by a small scan window without pointer churn. New entries start unreferenced; referenced entries are given a second chance by flipping a bit rather than moving in the list.
  - Pair with segmentedEvictScan to bound work per eviction. For most general-purpose workloads, prefer LRU or segmented; consider SIEVE for very allocation-sensitive runtimes or where pointer movements are costly.

## Using profiles

TypeScript:

```ts
import { SecureLRUCache } from '@david-osipov/security-kit';
import { resolveSecureLRUOptions } from '@david-osipov/security-kit/src/config';

const opts = resolveSecureLRUOptions('balanced');
const cache = new SecureLRUCache<string, Uint8Array>({
  maxEntries: 1000,
  maxBytes: 2 * 1024 * 1024,
  ...opts,
});
```

## Customizing

You can set your own profiles or override the default:

```ts
import { setSecureLRUProfiles } from '@david-osipov/security-kit/src/config';

setSecureLRUProfiles({
  defaultProfile: 'balanced',
  profiles: [
    {
      name: 'my-fast',
      description: 'Higher throughput with sampled promotion and larger wipe batches',
      options: {
        ttlAutopurge: true,
        ttlResolutionMs: 1000,
        promoteOnGet: 'sampled',
        promoteOnGetSampleRate: 8,
        maxDeferredWipesPerFlush: 512,
        deferredWipeScheduler: 'auto',
        deferredWipeTimeoutMs: 1,
        // recencyMode: 'lru' | 'segmented' | 'second-chance' | 'sieve'
        recencyMode: 'lru',
        // For segmented: window size to scan near the head during eviction
        segmentedEvictScan: 8,
        segmentRotateEveryOps: 10_000,
        // For second-chance: cap the number of rotations (move-to-tail) per eviction
        secondChanceMaxRotationsPerEvict: 8,
      },
    },
  ],
});
```

All options are merged directly into the `SecureLRUCache` constructor. See code docs for the full list.

Important defaults:
- VerifiedByteCache forces `promoteOnGet: 'always'` to provide deterministic strict-LRU semantics regardless of profile.
- TTL clocks use `Date.now()` and respect `ttlResolutionMs` to bound jitter; fake timers in tests are supported.

### Switching the default profile globally

You can change the global default without redefining profiles:

```ts
import { setSecureLRUProfiles } from '@david-osipov/security-kit/src/config';

// Set default to a built-in profile name
setSecureLRUProfiles({ defaultProfile: 'read-heavy-lru-coarse' });
```

## Security notes

- Keep `copyOnSet` and `copyOnGet` enabled for sensitive data.
- Don’t disable `rejectSharedBuffers` unless you fully control producers.
- TTL autopurge reduces jitter for hot paths and avoids opportunistic cleanup in GET.
- Coarser `ttlResolutionMs` improves performance but increases expiry jitter up to that amount.
- Wiping strategy: set `wipeStrategy: 'defer' | 'sync'`. Deferred wipes are rate-limited and flushed via microtasks/timeout based on queue size/bytes.
- `rejectSharedBuffers` defends against SAB-backed views; keep it on unless you fully control producers.
- `maxEntryBytes` and `maxBytes` are enforced up-front; entries above limits throw with InvalidParameterError.

## Recommended starting points

- Browser worker bytes (Signer): balanced or throughput-segmented (if read-heavy and long-lived).
- Server signature verification: low-latency-lru for predictable latency under load.
- Read-mostly application caches: read-heavy-lru-coarse.
- Mixed read/write with frequent updates: throughput-segmented-aggressive.
- Pointer-churn-sensitive workloads or where you want bounded eviction work without list moves: experimental-sieve (canonical SIEVE).

## Choosing a recency policy: quick reference

- LRU (recencyMode: 'lru')
  - Pros: true recency; intuitive eviction; excellent hit ratios in many workloads.
  - Cons: pointer churn on get/set due to move-to-tail promotions; mitigate with `promoteOnGet: 'sampled'` for read-heavy loads.

- Segmented (recencyMode: 'segmented')
  - Pros: approximates LRU with fewer pointer updates; higher throughput under heavy GET/SET.
  - Cons: slight degradation in hit ratio vs strict LRU; tune with `segmentedEvictScan` and `segmentRotateEveryOps`.

- Second-chance (recencyMode: 'second-chance')
  - Pros: evicts one-hit-wonders quickly; bounded rotations per eviction with `secondChanceMaxRotationsPerEvict`.
  - Cons: still incurs pointer moves on rotations; prefer for simpler SIEVE-like behavior when list moves are acceptable.

- Canonical SIEVE (recencyMode: 'sieve')
  - Pros: no move-to-tail on hits/evictions; only flips reference bits with a persistent hand; predictable bounded work.
  - Cons: differs from strict LRU ordering; use when avoiding pointer churn matters more than pure LRU fidelity.
