import { defineConfig } from "vitest/config";

// Environment-driven tuning knobs (safe defaults)
const HAPPY_TEST_TIMEOUT = Number(process.env.VITEST_TEST_TIMEOUT_HAPPY ?? "15000");
const HAPPY_HOOK_TIMEOUT = Number(process.env.VITEST_HOOK_TIMEOUT_HAPPY ?? "15000");
const HAPPY_TEARDOWN_TIMEOUT = Number(
  process.env.VITEST_TEARDOWN_TIMEOUT_HAPPY ?? "15000",
);
const HAPPY_ISOLATE =
  process.env.VITEST_HAPPY_ISOLATE !== undefined
    ? process.env.VITEST_HAPPY_ISOLATE !== "false"
    : true;

// NOTE: With 3k+ tests, running everything under jsdom is costly. We split into two
// projects: a fast Node project for most tests, and a jsdom project for DOM/sanitizer/postMessage.
// We also use the 'threads' pool for better throughput on large suites.

export default defineConfig({
  test: {
    pool: "threads",
    globals: true,
    // Consider disabling file isolation to speed up large suites if tests clean up after themselves.
    // See docs: https://vitest.dev/guide/improving-performance.html
    // For strict security tests we keep defaults; you can enable locally when profiling:
    // isolate: false,
    // Keep coverage config at root so it applies across projects
    coverage: {
      provider: "v8" as const,
      reporter: ["text", "json", "html", "lcov"],
      exclude: [
        "node_modules/**",
        "dist/**",
        "tests/**",
        "**/*.d.ts",
        "**/*.config.*",
        "coverage/**",
        "demo/**",
        "scripts/**",
        // Exclude non-runtime/type-only and harness files from coverage
        "src/protocol.ts",
        "src/scripts/**",
        "tools/**",
        "tmp-*/**",
        ".husky/**",
        ".vscode/**",
        ".github/**",
        ".sonarlint/**",
        ".mcp/**",
      ],
  include: ["src/**", "server/**", "tools/**", "scripts/**"],
      all: true,
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
    },
    // Define projects to isolate jsdom-specific setup & keep node tests lean
    projects: [
      {
        test: {
          name: "node",
          globals: true,
          environment: "node",
          // When debugging performance locally, you can run all Node tests in a single worker:
          // poolOptions: { threads: { singleThread: true, isolate: false } },
          exclude: [
            "node_modules/**",
            "dist/**",
            // Exclude jsdom-heavy tests so they run in the jsdom project only
            "tests/integration/**",
            "tests/**/dom*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/sanitizer*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/postMessage*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/postmessage*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/vmPostMessageHelper*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/blob-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            // Exclude worker/browser-dependent suites that require MessagePort, location, etc.
            "tests/**/signing-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/docs-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/api-signing*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/vulnerabilities-poc*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/secure-api-signer*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/signing-client*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/secure-lru-cache*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/utils.uncovered*.{test,spec}.?(c|m)[jt]s?(x)",
            // Needs document to exist for visibility tests
            "tests/**/crypto.hidden.spec.ts",
            "tests/unit/security.spec.ts",
          ],
        },
      },
      {
        test: {
          // Note: keeping the project name "jsdom" for script compatibility,
          // but we run Happy DOM for improved performance.
          name: "happy-dom",
          globals: true,
          environment: "happy-dom",
          setupFiles: ["tests/setup/global-dompurify.ts"],
          environmentOptions: {
            "happy-dom": {
              url: "http://localhost",
            },
          },
          // Slightly higher timeouts to accommodate DOM + worker-like flows
          testTimeout: HAPPY_TEST_TIMEOUT,
          hookTimeout: HAPPY_HOOK_TIMEOUT,
          teardownTimeout: HAPPY_TEARDOWN_TIMEOUT,
          // Allow opt-in isolation tuning via env for local runs; defaults remain strict.
          poolOptions: { threads: { isolate: HAPPY_ISOLATE } },
          // Happy DOM is significantly faster than jsdom for our needs. If you see any
          // discrepancies for specific APIs, temporarily switch to `environment: 'jsdom'` for that test file.
          // To squeeze more throughput locally, you may also experiment with disabling isolation for threads:
          // poolOptions: { threads: { isolate: false } },
          include: [
            "tests/integration/**",
            "tests/**/dom*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/sanitizer*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/postMessage*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/postmessage*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/vmPostMessageHelper*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/blob-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            // Route worker/browser-dependent suites here for proper globals (MessagePort, location)
            "tests/**/signing-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/docs-worker*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/api-signing*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/vulnerabilities-poc*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/secure-api-signer*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/signing-client*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/secure-lru-cache*.{test,spec}.?(c|m)[jt]s?(x)",
            "tests/**/utils.uncovered*.{test,spec}.?(c|m)[jt]s?(x)",
            // Requires document/global visibility controls
            "tests/**/crypto.hidden.spec.ts",
            "tests/unit/security.spec.ts",
          ],
        },
      },
    ],
    // Enable dependency optimizer for potentially faster transforms on big suites
    deps: {
      optimizer: {
        // Enable both SSR and Web modes to let Vitest prebundle deps when applicable
        ssr: { enabled: true },
        web: { enabled: true },
      },
    },
  },
  define: {
    __TEST__: true,
    "process.env.NODE_ENV": JSON.stringify("test"),
    "process.env.SECURITY_KIT_ALLOW_TEST_APIS": JSON.stringify("true"),
    "globalThis.__SECURITY_KIT_ALLOW_TEST_APIS": true,
  },
});
