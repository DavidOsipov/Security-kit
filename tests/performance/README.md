# Performance tests and tuning notes

This directory contains the SecureLRUCache performance tests and a short summary of the recent tuning investigation.

## Key findings (2025-09-02)

- SIEVE rotate interval (SEG_ROTATE_OPS) is not inherently pathological under eviction-heavy load; with stable wipe scheduling the tuned SIEVE profile produced consistent latencies around ~0.004 ms for DELETE across SEG_ROTATE_OPS ∈ {10, 1000, 10000}.
- Deferred wipe scheduler strongly affects DELETE latency:
  - For SEG_ROTATE_OPS=1000, forcing WIPE_SCHED=timeout caused ~4–5x slower DELETE (~0.018 ms) versus microtask (~0.004 ms).
  - Root cause: timeout-driven draining is more likely to kick in depending on wipe queue thresholds; microtask avoids that jitter.
- Debug counters corroborate health: sieveScans and evictions remain high under stable configurations and correlate with good steady state.

## Guardrails we added

- New benchmark harness profile: `sieve-microtask`. Pins WIPE_SCHED=microtask and raises thresholds for reproducible low-jitter runs.
- New code preset: `low-latency` in `src/config.ts` that enforces microtask wipe scheduling with higher auto thresholds and canonical SIEVE recency.
- Perf tests now set these env defaults if unset:
  - WIPE_SCHED=microtask, WIPE_AUTO_THRESH=512, WIPE_TIMEOUT_MS=0
    This avoids scheduler drift between local/CI.

## How to reproduce the sweep locally

Optional commands — run from repo root:

```bash
# Canonical SIEVE with microtask wipe scheduling
PROFILE=sieve-microtask BENCH_RUNS=1 node benchmarks/compare-lru-harness.mjs

# Eviction-heavy SIEVE, rotate interval variants
RECENCY_MODE=sieve SEG_SCAN=8 SEG_ROTATE_OPS=10 KEYSPACE=4096 MAX_ENTRIES=64 VALUE_BYTES=1024 BENCH_RUNS=1 WIPE_SCHED=microtask node benchmarks/compare-lru-harness.mjs
RECENCY_MODE=sieve SEG_SCAN=8 SEG_ROTATE_OPS=1000 KEYSPACE=4096 MAX_ENTRIES=64 VALUE_BYTES=1024 BENCH_RUNS=1 WIPE_SCHED=microtask node benchmarks/compare-lru-harness.mjs
RECENCY_MODE=sieve SEG_SCAN=8 SEG_ROTATE_OPS=10000 KEYSPACE=4096 MAX_ENTRIES=64 VALUE_BYTES=1024 BENCH_RUNS=1 WIPE_SCHED=microtask node benchmarks/compare-lru-harness.mjs
```

## Recommended defaults

- For CI and repeatable perf: prefer WIPE_SCHED=microtask or keep "auto" with higher thresholds (WIPE_AUTO_THRESH≥256, WIPE_AUTO_BYTES≥1MiB).
- Use the `low-latency` preset or `sieve-microtask` profile for low-jitter DELETE timing.

## Notes

- The benchmark harness now records additional env knobs in `_meta.env` for each run (wipe settings, size limits, iteration controls) to make forensic comparisons easier.
