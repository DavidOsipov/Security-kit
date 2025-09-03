import { test, expect, vi, beforeEach, afterEach } from "vitest";
import { secureDevelopmentLog } from "../../src/utils";
import { getLoggingConfig, setLoggingConfig } from "../../src/config";

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  // restore original logging config to avoid affecting other tests
  const orig = getLoggingConfig();
  setLoggingConfig({ rateLimitTokensPerMinute: orig.rateLimitTokensPerMinute });
  vi.restoreAllMocks();
});

test("dev logger rate-limit emits console.warn summary when tokens exhausted", () => {
  // Set a very small token bucket to trigger dropping quickly
  setLoggingConfig({ rateLimitTokensPerMinute: 1 });

  const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

  // First log should be emitted normally (consumes token)
  secureDevelopmentLog("info", "testComponent", "first dev log", { a: 1 });

  // Second log should be rate-limited and cause the summary warn to be printed
  secureDevelopmentLog(
    "info",
    "testComponent",
    "second dev log (should be dropped)",
    { b: 2 },
  );

  // There will be at least one console.warn for the first log's output (dev console)
  // and another console.warn for the rate-limit summary message. Ensure the summary was emitted.
  const calls = warnSpy.mock.calls.map((c) => String(c[0]));
  const hasRateLimit = calls.some((c) =>
    c.includes("[security-kit] dev log rate-limit: dropping"),
  );
  expect(hasRateLimit).toBeTruthy();

  // Cleanup
  warnSpy.mockRestore();
});
