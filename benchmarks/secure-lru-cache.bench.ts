import { Bench } from "tinybench";
import { SecureLRUCache } from "../src/secure-cache";

// Simple tinybench-style microbenchmark script for SecureLRUCache
// Measures SET, GET, DELETE operations and prints basic percentiles.

function nowMs() {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

async function main() {
  // Configure iterations explicitly for stable output
  const bench = new Bench({ now: nowMs, iterations: 2000 });

  const cache = new SecureLRUCache({
    maxEntries: 1000,
    maxBytes: 1024 * 1024,
    maxEntryBytes: 32 * 1024,
  });

  const value = new Uint8Array(1024);
  for (let i = 0; i < value.length; i++) value[i] = i & 0xff;

  const tSet = bench.add("SET", async () => {
    const k = Math.random().toString(36).slice(2, 10);
    const t0 = nowMs();
    cache.set(k, value);
    const t1 = nowMs();
    return { overriddenDuration: t1 - t0 };
  });

  const tGet = bench.add("GET", async () => {
    const k = Math.random().toString(36).slice(2, 10);
    cache.set(k, value);
    const t0 = nowMs();
    cache.get(k);
    const t1 = nowMs();
    return { overriddenDuration: t1 - t0 };
  });

  const tUpdate = bench.add("UPDATE", async () => {
    const k = Math.random().toString(36).slice(2, 10);
    cache.set(k, value);
    const t0 = nowMs();
    // perform an update (set on existing key)
    cache.set(k, value);
    const t1 = nowMs();
    return { overriddenDuration: t1 - t0 };
  });

  const tDelete = bench.add("DELETE", async () => {
    const k = Math.random().toString(36).slice(2, 10);
    cache.set(k, value);
    const t0 = nowMs();
    cache.delete(k);
    const t1 = nowMs();
    return { overriddenDuration: t1 - t0 };
  });

  bench.addEventListener("cycle", (evt: any) => {
    // evt.task.result contains statistics in tinybench - just print a short summary
    const task = evt?.task;
    const name = task?.name || "unknown";
    const r = task?.result;
    if (r && r.latency) {
      console.log(
        `${name} — mean: ${r.mean.toFixed(6)} ms  p95: ${r.p95?.toFixed(6)} ms  p99: ${r.p99?.toFixed(6)} ms`,
      );
    }
  });

  console.log("Warming up and running tinybench...");
  await (bench as any).run();

  // Print results and collect JSON
  const results: Record<string, any> = {};
  const benchTasks = (bench as any).tasks || [];
  for (const bt of benchTasks) {
    const name = bt?.name || bt?.id || "unknown";
    const r = bt?.result || bt?.stats || bt?.latency || null;
    // some tinybench versions put stats under .result, others under .stats
    if (!r) {
      console.log(`\n=== ${name} === (no result available)`);
      continue;
    }
    const mean = r.mean ?? (r.latency && r.latency.mean) ?? null;
    const p50 = (r.latency && r.latency.p50) ?? r.p50 ?? null;
    const p95 = r.p95 ?? (r.latency && r.latency.p95) ?? null;
    const p99 = r.p99 ?? (r.latency && r.latency.p99) ?? null;
    // try to extract samples array
    const samples: number[] = Array.isArray(r.samples)
      ? r.samples
      : Array.isArray(r.latency?.samples)
        ? r.latency.samples
        : [];
    const sorted = samples.slice().sort((a, b) => b - a);
    const outliers = sorted.slice(0, Math.min(10, sorted.length));

    const opsPerSec =
      typeof mean === "number" && mean > 0 ? Math.round(1000 / mean) : null;
    results[name] = {
      mean,
      p50,
      p95,
      p99,
      samples: samples.length,
      outliers,
      opsPerSec,
    };

    console.log(`\n=== ${name} ===`);
    if (typeof mean === "number") console.log(`mean: ${mean.toFixed(6)} ms`);
    if (typeof mean === "number")
      console.log(`ops/sec: ${Math.round(1000 / mean).toLocaleString()}`);
    if (typeof p50 === "number")
      console.log(
        `p50: ${p50.toFixed(6)} ms  p95: ${p95?.toFixed(6)} ms  p99: ${p99?.toFixed(6)} ms`,
      );
    console.log(
      `samples: ${samples.length}  top-outliers(ms): ${outliers.map((x) => x.toFixed(6)).join(", ")}`,
    );
  }

  // write results JSON
  try {
    const fn = `benchmarks/results-secure-lru-cache-${Date.now()}.json`;
    await import("fs").then((m) =>
      m.promises.writeFile(fn, JSON.stringify(results, null, 2), "utf8"),
    );
    console.log("\nWrote JSON results to", fn);
  } catch (err) {
    console.error("Failed to write JSON results:", err);
  }

  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
