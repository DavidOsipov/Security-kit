Fast-check CI integration

This repository runs a conservative fast-check property test during CI and a deeper
fast-check run on a scheduled/nightly job.

How it works

- CI run: sets FASTCHECK_RUNS=200 and executes the runtime property test
  `tests/security/property-based.handshake-and-sign.runtime.test.ts` to catch
  regressions quickly in PRs.
- Nightly run: triggered by schedule or manual workflow dispatch and runs with
  FASTCHECK_MODE=nightly and FASTCHECK_RUNS=2000 for deeper exploration.

Local runs

- Quick local run (CI-like):
  FASTCHECK_RUNS=200 npm test -- tests/security/property-based.handshake-and-sign.runtime.test.ts
- Nightly/deep local run:
  FASTCHECK_MODE=nightly FASTCHECK_RUNS=2000 npm test -- tests/security/property-based.handshake-and-sign.runtime.test.ts

Seeded reproduction

- To reproduce a failing case reported in CI, set FASTCHECK_SEED to the failing
  seed reported in the error message and run the same command above.
