# Future work: telemetry enrichment, mutation testing with Stryker, and fuzzing with fast-check

This document describes a focused plan to further harden `secureCompareAsync` and related crypto paths, increase observability for rare failure modes, and add strong automated tests that guard against regressions (fuzzing + mutation testing).

## Goal

1. Telemetry enrichment: record precise "reason" for fallback vs failure so we can triage issues in production and detect adversarial probing.
2. Mutation testing with Stryker: ensure tests actually prevent accidental re-introduction of insecure fallbacks and other logic regressions.
3. Fuzz testing with fast-check: exercise error paths by throwing a variety of values and error types to ensure `secureCompareAsync` fails closed for all unexpected cases.

## Rationale

- OWASP ASVS L3 requires high assurance: library code must not silently degrade cryptographic primitives.
- Adversaries may try to trigger engine edge-cases (throwing getters, exotic exceptions) to force fallback paths. Explicit telemetry and strong tests mitigate that risk.
- Mutation testing raises confidence that tests catch behavioral changes rather than just executing code.

## Telemetry enrichment

Add nuance to emitted telemetry for `secureCompareAsync` and related helpers.

Fields to add:

- `reason`: one of `"unavailable"` | `"unexpected"` | `"wipe-failed"` to indicate why crypto path failed.
- `requireCrypto`: `"1"` or `"0"` (existing)
- `subtlePresent`: `"1"` | `"0"` | `"unknown"` (existing-ish)
- `strict`: `"1"` | `"0"`

Usage example (pseudocode):

- When `ensureCrypto()` rejects with `CryptoUnavailableError`:
  safeEmitMetric('secureCompare.fallback', 1, { reason: 'unavailable', requireCrypto: '0', subtlePresent: '0', strict: '0' });
- When any unexpected exception occurs in the crypto path:
  safeEmitMetric('secureCompare.error', 1, { reason: 'unexpected', requireCrypto: '0', strict: '0' });
- When secureWipe returns false during crypto cleanup:
  safeEmitMetric('secureCompare.error', 1, { reason: 'wipe-failed', requireCrypto: '1', strict: '1' });

Implementation notes:

- Keep telemetry surface small and allowlist tag keys using existing `METRIC_TAG_ALLOW` and `sanitizeMetricTags` helpers.
- Use `safeEmitMetric` for all emissions so user-provided telemetry hooks cannot destabilize the lib.

## Mutation testing with Stryker

Why:

- Mutation testing verifies that tests fail when the implementation changes in ways that weaken security (for example, reintroducing an unexpected fallback path that returns `secureCompare(sa, sb)` on arbitrary errors).

Plan:

1. Add `stryker` to `devDependencies` (use the latest stable StrykerJS package). Prefer the modern package `@stryker-mutator/core`.
2. Add `stryker.conf.json` or `stryker.conf.js` in repo root with these key settings:
   - testRunner: 'vitest'
   - mutator: 'typescript' (or 'javascript' if using compiled output)
   - packageManager: 'npm'
   - reporters: ['progress', 'clear-text', 'html']
   - thresholds: high (e.g., high: 90, low: 80, break: 70) for strictness
   - mutate: target only `src/utils.ts` initially, and limit to a small set of critical functions (e.g., `handleCompareError`, `compareWithCrypto`) to keep runtime manageable
3. Add an npm script `mutate`:
   "mutate": "npx stryker run"
4. Run locally and iterate on tests to raise mutation score. Focus on adding tests that specifically assert thrown behavior for unexpected errors.

Resource/CI notes:

- Mutation is CPU heavy; run it on dedicated CI runners or nightly jobs.
- Use Stryker's `timeoutFactor` and `maxConcurrentTestRunners` to tune performance on CI.

## Fuzzing with fast-check

Why:

- Fuzzing exercises many edge-cases quickly and can generate exotic inputs and thrown values.

Plan:

1. Add `fast-check` to `devDependencies` (already present in project; use existing version).
2. Add a `tests/fuzz/secureCompareAsync.fuzz.test.ts` that:
   - Mocks `ensureCrypto()` to resolve to a normal crypto object with `subtle.digest` stubbed.
   - For each generated arbitrary (errors: Error instances, custom Error subclasses, strings, numbers, symbols, objects, functions, undefined, null, BigInt), cause the `subtle.digest` promise to reject with that arbitrary value.
   - Assert that `secureCompareAsync` rejects with `CryptoUnavailableError` for all non-`CryptoUnavailableError` thrown values.

Example outline (fast-check pseudo-code):

- fc.assert(fc.asyncProperty(fc.oneof(...errorGenerators), async (err) => { mock digest to reject err; await expect(secureCompareAsync('a','b')).rejects.toThrow(CryptoUnavailableError); }))

Tuning:

- Limit number of runs (e.g., 1000) for CI; run more locally when investigating.
- Use `fc.scheduler` to produce sequences that include thrown getters and side-effectful values.

## CI integration

- Add `npm run mutate` as a nightly job (not required for every PR) — it’s resource-heavy.
- Add `npm run fuzz` for targeted fuzz test runs in PRs if a flag is set (or run with `--runs 100` for CI smoke).

## Commands

- Install Stryker core:

```bash
npm install -D @stryker-mutator/core @stryker-mutator/vitest-runner
```

- Run mutation testing:

```bash
npm run mutate
```

- Run fuzz tests (example):

```bash
npx vitest run tests/fuzz/secureCompareAsync.fuzz.test.ts
```

## Next steps (short-term)

1. Implement telemetry reasons in the codebase and export a test helper for verifying metric payloads.
2. Add the focused fast-check fuzz test described above.
3. Add a small Stryker configuration that targets `src/utils.ts` and iterate until mutation score is acceptable.

## Appendix: Example `stryker.conf.json` snippet

{
"mutator": "typescript",
"packageManager": "npm",
"testRunner": "vitest",
"reporters": ["progress", "clear-text", "html"],
"coverageAnalysis": "off",
"mutate": ["src/utils.ts"],
"thresholds": { "high": 90, "low": 80, "break": 70 }
}

## Appendix: Example fast-check test sketch

// tests/fuzz/secureCompareAsync.fuzz.test.ts
import fc from 'fast-check';
import { secureCompareAsync } from '../../src/utils';

describe('fuzz: secureCompareAsync', () => {
it('rejects on unexpected crypto errors', async () => {
await fc.assert(
fc.asyncProperty(
fc.oneof(fc.string(), fc.integer(), fc.object(), fc.constant(undefined)),
async (err) => {
// stub subtle.digest to reject with `err`
// assert secureCompareAsync rejects with CryptoUnavailableError
},
),
{ numRuns: 200 },
);
});
});

---

If you'd like, I can also:

- Add the `FUTURE-PLANS.md` file now (done),
- Create the Stryker config and a starter mutation npm script,
- Add the skeleton fast-check fuzz test and one working case,
- Add CI snippets for nightly mutation runs.

Which of those would you like me to do next? (I can implement the Stryker config and a single seed fuzz test in this session.)
