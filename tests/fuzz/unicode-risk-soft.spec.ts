import { describe, it, expect } from "vitest";
import { analyzeUnicodeString } from "../../src/canonical.ts";

// Soft risk assessment focus: ensure metrics appear and remain stable shape.

describe("unicode-risk-soft", () => {
  it("flags variation selectors in risk metrics", () => {
    const s = "a\uFE0Fb"; // variation selector
    const analysis = analyzeUnicodeString(s);
    const variation = analysis.risk.metrics.find(m => m.id === "variationSelectors");
    expect(variation).toBeDefined();
    if (variation) expect(variation.triggered).toBe(true);
  });

  it("includes introducedStructural detail when applicable", () => {
    const fullwidth = "："; // U+FF1A -> ':'
    if (fullwidth.normalize("NFKC") !== ":") return;
    const analysis = analyzeUnicodeString(fullwidth);
    const structural = analysis.risk.metrics.find(m => m.id === "introducedStructural");
    expect(structural).toBeDefined();
    if (structural) {
      expect(structural.triggered).toBe(true);
      expect(structural.detail).toBeDefined();
    }
  });
});
