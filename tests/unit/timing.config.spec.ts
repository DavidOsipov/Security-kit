import { describe, it, expect } from "vitest";
import { secureCompare, secureCompareAsync } from "../../src/utils";
import { setTimingConfig } from "../../src/config";

describe("Timing config integration", () => {
  it("secureCompare honors small devEqualizeSyncMs without excessive delay", () => {
    setTimingConfig({ devEqualizeSyncMs: 1 });
    const t0 = Date.now();
    const eq = secureCompare("a", "a");
    const dt = Date.now() - t0;
    expect(eq).toBe(true);
    // Should not take hundreds of ms as older defaults; allow a small margin
    expect(dt).toBeLessThan(50);
  });

  it("secureCompareAsync honors small devEqualizeAsyncMs", async () => {
    setTimingConfig({ devEqualizeAsyncMs: 4 });
    const t0 = Date.now();
    const eq = await secureCompareAsync("abc", "abc");
    const dt = Date.now() - t0;
    expect(eq).toBe(true);
    // Should be bounded; allow margin for CI jitter but far less than 128ms legacy
    expect(dt).toBeLessThan(100);
  });
});
