import { describe, it, expect, vi } from "vitest";

// This stress test spawns many concurrent callers to the internal
// __test_ensureFingerprintSalt() API. It's intentionally slow at high
// concurrency; use STRESS_CONCURRENCY env var to tune (default 100 for
// CI/quick runs, but the test supports 500-1000 for local stress testing).

const DEFAULT_CONCURRENCY = 100;

async function loadWithMockedEnsureCrypto(
  ensureCryptoImpl: () => Promise<any>,
) {
  vi.resetModules();
  vi.doMock("../../src/state", () => ({
    ensureCrypto: ensureCryptoImpl,
    __test_resetCryptoStateForUnitTests: () => {},
    _setCrypto: () => {},
  }));
  vi.doMock("../../src/environment", () => ({
    environment: { isProduction: false },
    isDevelopment: () => true,
  }));
  const pm = await import("../../src/postMessage");
  return pm;
}

describe("ensureFingerprintSalt stress test (manual)", () => {
  it("runs high concurrency callers", async () => {
    const concurrency = Number(
      process.env.STRESS_CONCURRENCY ?? DEFAULT_CONCURRENCY,
    );
    // Ensure we don't accidentally run huge numbers in CI by mistake
    if (concurrency > 2000) throw new Error("STRESS_CONCURRENCY too large");

    let calls = 0;
    // Mock ensureCrypto with a slight delay to better exercise in-flight deduping
    const mockEnsure = async () => {
      calls += 1;
      // small random jitter to simulate realistic service startup delays
      const jitter = 5 + Math.floor(Math.random() * 15);
      vi.useFakeTimers();
      try {
        setTimeout(() => {}, jitter);
        vi.advanceTimersByTime(jitter);
        await vi.runAllTimersAsync();
      } finally {
        vi.useRealTimers();
      }
      return {
        getRandomValues: (u: Uint8Array) => {
          for (let i = 0; i < u.length; i++) u[i] = (i * 31) & 0xff;
          return u;
        },
      } as any;
    };

    const pm = await loadWithMockedEnsureCrypto(mockEnsure);
    try {
      pm.__test_resetForUnitTests();
    } catch {}

    // Per-caller timing to compute latency distribution
    const start = Date.now();
    const perStart: number[] = new Array(concurrency);
    const promises: Promise<Uint8Array>[] = [];
    for (let i = 0; i < concurrency; i++) {
      perStart[i] = Date.now();
      promises.push(pm.__test_ensureFingerprintSalt());
    }

    const results = await Promise.all(promises);
    const perEnd = results.map((_, i) => Date.now());
    const latencies = perEnd.map((t, i) => t - perStart[i]);
    const durationMs = Date.now() - start;

    // Compute basic percentile metrics
    const sorted = [...latencies].sort((a, b) => a - b);
    const p = (p: number) => {
      const idx = Math.floor(p * (sorted.length - 1));
      return sorted[idx] ?? 0;
    };
    const p50 = p(0.5);
    const p95 = p(0.95);
    const p99 = p(0.99);
    const min = sorted[0] ?? 0;
    const max = sorted[sorted.length - 1] ?? 0;

    // Memory telemetry snapshot
    const mem =
      typeof process !== "undefined" &&
      typeof process.memoryUsage === "function"
        ? process.memoryUsage()
        : undefined;

    // Telemetry output
    // eslint-disable-next-line no-console
    console.log(
      JSON.stringify(
        {
          stress: { concurrency, calls, durationMs, min, p50, p95, p99, max },
          mem,
        },
        null,
        2,
      ),
    );

    expect(results.length).toBe(concurrency);
    expect(calls).toBeGreaterThanOrEqual(1);

    // allow some leeway for platform scheduling; default max is 5
    const maxAllowed = Number(process.env.STRESS_MAX_ENSURE_CRYPTO_CALLS ?? 5);
    expect(calls).toBeLessThanOrEqual(maxAllowed);

    // Referential equality assertion: all callers should receive the same cached buffer
    const first = results[0];
    const allSameRef = results.every((r) => r === first);
    expect(allSameRef).toBe(true);

    // Latency SLO: at least STRESS_LATENCY_PERCENT of callers should finish under threshold
    const thresholdMs = Number(process.env.STRESS_LATENCY_THRESHOLD_MS ?? 200);
    const neededPercent = Number(process.env.STRESS_LATENCY_PERCENT ?? 0.95);
    const under =
      sorted.filter((v) => v <= thresholdMs).length / (sorted.length || 1);
    // eslint-disable-next-line no-console
    console.log(
      `latency: p50=${p50} p95=${p95} p99=${p99} threshold=${thresholdMs} under=${under}`,
    );
    expect(under).toBeGreaterThanOrEqual(neededPercent);
    // Ensure salt was generated and cached and is the right type
    expect(results.every((r) => r instanceof Uint8Array)).toBe(true);
  }, 120_000);
});
