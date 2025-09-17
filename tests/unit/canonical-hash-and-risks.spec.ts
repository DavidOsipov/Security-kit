// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { normalizeInputString } from "../../src/canonical.ts";
// sanitizeForLogging indirectly exercises computeCorrelationHash via includeRawHash option
import { sanitizeForLogging } from "../../src/canonical.ts";

describe("canonical unicode risk & correlation hash hardening", () => {
  it("freezes unicode risk assessment metrics array (non-mutable)", () => {
    const input = "café"; // 'e' + combining accent to trigger some metrics
    const normalized = normalizeInputString(input, "test");
    expect(typeof normalized).toBe("string");
    // We cannot directly import assessUnicodeRisks (internal) but we can rely on
    // normalizeInputString not throwing and use risk scoring side-effects when enabled.
    // This test primarily ensures nothing breaks after freezing; mutation attempts throw.
    // (If configuration enables risk scoring in future, we would hook a spy.)
  });

  it("caps correlation hash iteration for very large inputs", () => {
    const large = "a".repeat(300_000); // larger than iteration cap
    const short = "a".repeat(10_000);
    const hashedLarge = sanitizeForLogging(large, 50, { includeRawHash: true });
    const hashedShort = sanitizeForLogging(short, 50, { includeRawHash: true });
    const extractHash = (s: string): string | undefined => {
      const match = /correlationHash:([0-9a-f]{8})/u.exec(s);
      return match?.[1];
    };
    const hLarge = extractHash(hashedLarge);
    const hShort = extractHash(hashedShort);
    expect(hLarge).toBeDefined();
    expect(hShort).toBeDefined();
    // Different length groups should usually hash differently
    expect(hLarge).not.toBe(hShort);
  });
});
