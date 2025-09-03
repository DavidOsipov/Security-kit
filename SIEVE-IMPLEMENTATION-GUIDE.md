SIEVE policy implementation guide

## Goal

Implement a production-grade SIEVE recency policy for SecureLRUCache as an alternative to LRU and segmented. The SIEVE policy should provide an approximation of recency with a low-pointer-churn approach (second-chance-like semantics) while keeping strong security guarantees (zeroization, bounded sync evictions, etc.).

## Design overview

1. Data structures
   - Use an existing doubly-linked array model (keyList, valList, next, prev).
   - Add a low-memory "reference" bit per entry (`sieveRef: Uint8Array`) where `1` means recently referenced and `0` means not referenced.
   - New entries initialize as `0` (unreferenced) to evict one-hit-wonders efficiently.

2. Get semantics
   - On a cache hit in SIEVE mode, set sieveRef[index] = 1.
   - Avoid moving pointers for every get. Only clear the bit and move-to-tail during eviction passes.

3. Set semantics
   - For new entries, insert at the tail as with normal LRU.
   - For existing entries, update value/ttl, and set sieveRef[index] = 1.

4. Eviction algorithm
   - When eviction is required, scan a small window (configurable `sieveScan`, reusing `segmentedEvictScan`) from head up to N nodes:
     - If a node has sieveRef==0, evict it immediately.
     - If a node has sieveRef==1, clear it (surrender second chance) and move it to tail (rotate); continue scanning.
   - If no candidate found in window, fall back to evicting the head (to guarantee progress).
   - Ensure the scan is strictly bounded (<= segmentedEvictScan) to avoid unbounded CPU.

5. Interaction with other knobs
   - `promoteOnGet` should be respected only when set to `always` and recencyMode === 'lru'. For SIEVE, GET sets the reference bit regardless of promoteOnGet.
   - `segmentRotateEveryOps` is not used by SIEVE; reuse as noop or doc note.

6. Concurrency and safety
   - The cache is single-threaded JS. Maintain current invariants: maxSyncEvictions guard, pre-callback wipe guarantee, deferred wipes.
   - When moving nodes to tail during second-chance rotation, update prev/next pointers with the same O(1) operations used by `#moveToTail`.

7. Stats and observability
   - Record evictions as capacity evictions.
   - Optionally expose a small counter for `sieveRotations` and `sieveScans` to help tuning.

8. Tuning knobs
   - `segmentedEvictScan` (reused): how many nodes to scan per eviction attempt.
   - Added `sieveMaxRotationsPerEvict` to limit rotation churn if many nodes are referenced (defaults to `segmentedEvictScan`).

9. Testing
   - Unit tests to validate second-chance behavior:
     - Fill small cache, reference some keys, insert to force eviction, expect non-referenced keys to be evicted.
     - Ensure rotation does not produce pointer corruption (validate list invariants after series of ops).
     - Validate pre-callback wipe semantics remain correct.
   - Integration tests: include `experimental-sieve` profile test (already added) and add more stress tests with higher concurrency (simulated via repeated loops) to ensure steady-state.

10. Migration and backwards compatibility
    - Keep `recencyMode` union backward-compatible.
    - Add `experimental-sieve` profile as opt-in only.

11. Performance measurement

- Use the existing `compare-lru-harness.mjs` and the `sweep-segmented-tuning.mjs` (adapted to run sieve tunables) to measure GET/SET/UPDATE performance.
- Diagnostics exposed via `getDebugStats()` include `sieveScans` and `sieveRotations`.

## Implementation checklist

- [x] Add `sieveRef: Uint8Array` to `SecureLRUCache` constructor and initialize.
- [x] Initialize new entries with `sieveRef=0`.
- [x] Add optional `sieveMaxRotationsPerEvict` tuning knob.
- [x] Add diagnostics: `sieveScans`, `sieveRotations` with `getDebugStats()`.
- [ ] Implement set/get updates for sieveRef.
- [ ] Implement eviction branch for `recencyMode === 'sieve'` following second-chance semantics.
- [ ] Add small counters for diagnostics (optional) and expose via `getStats()` or a separate debug API.
- [ ] Add unit and integration tests covering correctness and performance.
- [ ] Run micro-sweeps to find best `segmentedEvictScan` values for SIEVE.

## Security considerations

- Ensure any pointer moves performed during rotation clear sensitive data invariants.
- Make no changes to zeroization/wipe guarantees: wiped buffers must be wiped before onEvict callback.
- Avoid additional data structures that may keep copies of sensitive values.

## Notes

The current prototype in `src/secure-lru-cache.ts` includes a basic sieveRef implementation. The above checklist expands the productionization steps and tests required before promoting SIEVE to a non-experimental profile.
