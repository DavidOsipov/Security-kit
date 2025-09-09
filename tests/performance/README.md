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


### The Strategy: Identify Bottlenecks, Then Profile Them

Your goal is not to profile 300kb of code. Your goal is to find the **5%** of the code that is causing **95%** of the performance problems under real-world conditions.

---

### Step 1: Find the Slow Spots with High-Level Tools

First, you need to identify which parts of your application are actually slow. You don't do this by reading code; you do this by running the application and measuring it.

#### Tool of Choice: `clinic.js`

For Node.js, the single best starting point for this is the **`clinic.js`** suite of tools. It's a fantastic, open-source project designed to diagnose Node.js performance issues automatically. It bundles several tools that work together.

**How to get started:**

1.  **Install Clinic.js and a load testing tool:** `autocannon` is made by the same team and integrates perfectly.

    ```bash
    npm install -g clinic autocannon
    ```

2.  **Run your application with `clinic doctor`:** The "doctor" will analyze your application under load and suggest what kind of problem you have (Is it a CPU issue? An I/O delay? A memory leak?).

    Let's say your app's entry point is `server.js` (the compiled output of your `server.ts`).

    In one terminal, start the doctor. It will run your server and wait for requests:

    ```bash
    clinic doctor -- node dist/server.js
    ```

3.  **Apply load with `autocannon`:** In a *second* terminal, hammer a critical API endpoint of your application. For example, if you have a complex data processing endpoint at `/api/process`:

    ```bash
    autocannon http://localhost:3000/api/process
    ```

4.  **Analyze the results:**
    *   Let autocannon run for 10-20 seconds, then stop it (`Ctrl+C`).
    *   Stop the `clinic` process in the first terminal (`Ctrl+C`).
    *   Clinic.js will automatically generate an HTML report and open it for you.

The **Doctor** report is your starting point. It will give you a clear recommendation, like:
*   "We've detected a CPU bottleneck. We recommend using **Clinic Flame** to investigate."
*   "We've detected an I/O issue. We recommend using **Clinic Bubbleprof**."
*   "We've detected a memory issue. We recommend using **Clinic Heap-Profiler**."

### Step 2: Deep Dive with the Right Tool

Now that Doctor has pointed you in the right direction, you can do a more focused analysis.

#### Scenario A: The Doctor says it's a CPU problem.

This is the most common case for code that is doing heavy computation, complex validation, or running inefficient loops—exactly what a security library might do.

1.  **Run `clinic flame`:** This is the same process as before, but it will generate a detailed Flame Graph. Remember to have **source maps** enabled in your `tsconfig.json`!

    ```bash
    # Terminal 1
    clinic flame -- node dist/server.js

    # Terminal 2 (after the server starts)
    autocannon http://localhost:3000/api/process
    ```

2.  **Analyze the Flame Graph:**
    *   Stop both processes. An HTML report will be generated.
    *   This time, you will get a detailed Flame Graph. **You don't need to look at the whole graph.** Look for the **widest bars at the top**.
    *   Because you have source maps, hovering over these bars will show you the exact TypeScript function name, file, and line number that is consuming the most CPU.
    *   **This is your bottleneck.** You have now successfully bypassed 99% of your codebase and found the exact function that needs optimization, without reviewing it manually.

#### Scenario B: The Doctor says it's an I/O problem.

This happens when your application is spending most of its time waiting for the network, database, or file system. Node.js is async, and it can be hard to see where these delays are.

1.  **Run `clinic bubbleprof`:** This tool is specifically designed to visualize async activity in Node.js.

    ```bash
    # Terminal 1
    clinic bubbleprof -- node dist/server.js

    # Terminal 2
    autocannon http://localhost:3000/api/process
    ```

2.  **Analyze the Bubbleprof Graph:** The report will show you a graph of all your async operations and draw lines representing the delays between them. Large empty spaces are periods where your app was just waiting. This helps you immediately spot if a slow database query or external API call is the root cause of your slow endpoint.

### Step 3: Prevent Regressions with Benchmarking

Once you've identified and fixed a bottleneck, you want to make sure it doesn't come back. This is where your Vitest tests come in.

1.  **Create a benchmark test:** Write a `*.bench.ts` file that specifically targets the function or logic you just optimized.
2.  **Run it and record the result:** Run `vitest bench` and see the "ops/sec" (operations per second).
3.  **Integrate into CI:** You can run these benchmarks as part of your CI/CD pipeline. While you might not fail the build on a small regression, you can set up alerts if a key benchmark's performance drops by more than 10-15%, letting you know immediately that a recent change introduced a performance problem.

### Summary: The Optimal Workflow

1.  **Don't guess.** Don't profile individual functions.
2.  **Identify Critical Paths:** Determine the most important user-facing actions or API endpoints in your application.
3.  **Run `clinic doctor`** while applying load to these critical paths with `autocannon`.
4.  **Follow the Doctor's advice:** Use `clinic flame` (for CPU) or `clinic bubbleprof` (for I/O) to get a detailed visualization that points directly to the bottleneck in your TypeScript code.
5.  **Fix the problem** in that specific, identified area.
6.  **Write a benchmark test (`vitest bench`)** for the fixed code to ensure the problem never silently reappears.

This top-down approach is far more efficient and effective. It lets you use your time analyzing and fixing the few parts of the code that actually matter for performance.