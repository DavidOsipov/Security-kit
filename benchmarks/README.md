# Benchmarks helper scripts

This folder contains helper scripts used for steady-state microbenchmarks and small parameter sweeps.

Scripts
- `compare-lru-harness.mjs` — apples-to-apples harness for SecureLRU and other LRU libs. Accepts optional profile name as argv[2] or `PROFILE` env var.
- `summarize-profiles.mjs` — parse the last N `results-compare-lru-*.json` files and emit `summary-*.json` files (global and per-profile) for CI scraping. Usage:

```bash
# summarize last 10 results
node benchmarks/summarize-profiles.mjs benchmarks 10
```

- `sweep-segmented-tuning.mjs` — small grid sweep for segmented tuning. Use `ITERATIONS_PER_POINT` env var to run multiple iterations per config point. Example:

```bash
# run 3 iterations per point
ITERATIONS_PER_POINT=3 node benchmarks/sweep-segmented-tuning.mjs
```

CI
- A GitHub Action workflow `.github/workflows/bench-summary-publish.yml` is provided to run the harness and publish `benchmarks/summary-*.json` as artifacts.
