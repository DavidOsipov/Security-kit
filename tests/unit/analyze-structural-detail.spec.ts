import { describe, it, expect } from "vitest";
import { analyzeUnicodeString, normalizeInputString } from "../../src/canonical.ts";
import { UnicodeErrorCode, InvalidParameterError } from "../../src/errors.ts";

function getMetric(assessment: ReturnType<typeof analyzeUnicodeString>["risk"], id: string) {
  return assessment.metrics.find(m => m.id === id);
}

describe("analyzeUnicodeString introducedStructural detail", () => {
  it("provides detail with chars and samples when structural chars introduced", () => {
    const fullwidth = "："; // U+FF1A fullwidth colon -> ':'
    // Confirm environment actually normalizes; if not, skip
    if (fullwidth.normalize("NFKC") !== ":") {
      return; // noop in anomalous environment
    }
    const analysis = analyzeUnicodeString(fullwidth);
    const metric = getMetric(analysis.risk, "introducedStructural");
    expect(metric).toBeDefined();
    if (!metric) return;
    expect(metric.triggered).toBe(true);
    expect(metric.detail && (metric.detail as any).chars).toBeDefined();
    const detail = metric.detail as { chars: string[]; samples: Array<{ ch: string; index: number }> };
    expect(detail.chars.length).toBeGreaterThan(0);
    expect(detail.samples.length).toBeGreaterThan(0);
    expect(detail.samples[0]).toHaveProperty("ch");
    expect(detail.samples[0]).toHaveProperty("index");
  });

  it("does not trigger when no structural introduction occurs", () => {
    const analysis = analyzeUnicodeString("simple-value");
    const metric = getMetric(analysis.risk, "introducedStructural");
    expect(metric).toBeDefined();
    if (!metric) return;
    expect(metric.triggered).toBe(false);
    expect(metric.detail).toBeUndefined();
  });
});
