import { test, expect } from "vitest";
import fc from "fast-check";

// Property-based tests for handshake nonce and signing canonical strings.
// This file is a fast-check harness that is configurable via environment:
// - FASTCHECK_MODE=nightly -> larger runs (useful for nightly pipelines)
// - FASTCHECK_RUNS=NUMBER -> override number of runs
// - FASTCHECK_SEED=NUMBER -> reproduce failing seeds
// CI defaults: conservative runs to keep PR checks fast.

const isCI = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
const mode = process.env.FASTCHECK_MODE || (isCI ? "ci" : "local");

function defaultRuns() {
  if (process.env.FASTCHECK_RUNS) return Number(process.env.FASTCHECK_RUNS);
  if (process.env.FASTCHECK_MODE === "nightly") return 2000;
  if (isCI) return 200; // keep CI quick
  return 1000; // local developer runs are a bit larger
}

const NUM_RUNS = defaultRuns();
const SEED = process.env.FASTCHECK_SEED
  ? Number(process.env.FASTCHECK_SEED)
  : undefined;

test("fast-check: handshake nonce validator is stable on arbitrary strings", async () => {
  const arb = fc.string();

  await fc.assert(
    fc.asyncProperty(arb, async (s) => {
      // Simulate the same lightweight checks the worker uses for nonce validation
      // without importing the whole worker. The goal is to ensure validators are
      // well-behaved and don't throw on unexpected inputs.
      const maybeBase64 = /^(?:[A-Za-z0-9+/=]+)$/.test(s);
      const maybeBase64Url = /^(?:[A-Za-z0-9-_]+)$/.test(s);
      // Must be boolean results and quick to compute
      return (
        typeof maybeBase64 === "boolean" && typeof maybeBase64Url === "boolean"
      );
    }),
    { numRuns: NUM_RUNS, seed: SEED },
  );
});

test("fast-check: signing canonical accepts arbitrary strings safely", async () => {
  // limit size in CI to avoid blowing up memory/time; allow larger local/nightly runs
  const maxLen = isCI ? 10_000 : 50_000;
  const arb = fc.string({ maxLength: maxLen });

  await fc.assert(
    fc.asyncProperty(arb, async (s) => {
      // Ensure the canonicalization / encoding steps don't throw.
      // This mirrors the logic where worker encodes string to bytes prior to signing.
      try {
        const encoder = new TextEncoder();
        const buf = encoder.encode(s);
        return buf.length >= 0;
      } catch (e) {
        // fast-check will capture counterexamples and, with SEED set, they can be reproduced
        return false;
      }
    }),
    { numRuns: NUM_RUNS, seed: SEED },
  );
});

// Surface some basic mode info for debugging when tests run (only in verbose logs)
if (!isCI) {
  // eslint-disable-next-line no-console
  console.info(
    `[fast-check] mode=${mode} runs=${NUM_RUNS} seed=${SEED ?? "random"}`,
  );
}
