import { describe, it, expect, beforeEach, vi } from "vitest";
import { secureDevLog, _redact, registerTelemetry } from "../../src/utils";
import { environment } from "../../src/environment";
import { setLoggingConfig } from "../../src/config";

describe("secureDevLog rate limiting", () => {
  beforeEach(() => {
    environment.setExplicitEnv("development");
    environment.clearCache();
    // reset to default rate limit
    setLoggingConfig({ rateLimitTokensPerMinute: 10 });
  });

  it("drops logs when rate exceeded and emits telemetry", async () => {
    const metric = vi.fn();
    const unregister = registerTelemetry(metric);

    // produce more than 10 logs quickly
    for (let i = 0; i < 15; i++) {
      secureDevLog("info", "test", "msg", { i });
    }

    // Wait for microtask to complete
    await new Promise((resolve) => setTimeout(resolve, 0));

    // The telemetry hook should have been called for rate hits (name contains 'logRateLimit.hit')
    const called = metric.mock.calls.some(
      (c: any[]) => c[0] === "logRateLimit.hit",
    );
    expect(called).toBe(true);

    unregister();
  });
});
