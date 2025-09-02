Security-kit - Performance Tests (opt-in)

Overview

This repository contains opt-in performance benchmarks for security-sensitive modules. These tests are intentionally excluded from normal CI and default test runs because they:

- require Node's `--expose-gc` to exercise GC behavior deterministically,
- can be noisy and environment-sensitive,
- are intended for local profiling and periodic regression checks.

Running the perf tests

Install dev dependencies (if not already installed):

```bash
npm install
```

Run all performance tests (exposes GC and uses a minimal Vitest config):

```bash
npm run perf
```

Run a single file with GC exposed (example):

```bash
NODE_OPTIONS=--expose-gc npx vitest run tests/performance/crypto-security-performance.test.ts -c vitest.min.config.mjs
```

Notes

- These tests are best run on an idle machine with consistent CPU scaling and minimal background activity.
- Thresholds in tests are intentionally loose; use them as safety checks, not strict performance budgets.
- Prefer adding CI perf jobs as optional scheduled workflows if you want regular regression detection.
