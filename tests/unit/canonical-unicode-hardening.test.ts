// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from "../../src/config.ts";
import { normalizeInputString, analyzeUnicodeString } from "../../src/canonical.ts";
import { InvalidParameterError } from "../../src/errors.ts";

// Utility to safely mutate config for a single test then restore
function withConfig(patch: Partial<ReturnType<typeof getUnicodeSecurityConfig>>, fn: () => void) {
  const original = getUnicodeSecurityConfig();
  setUnicodeSecurityConfig(patch);
  try { fn(); } finally { setUnicodeSecurityConfig(original); }
}

describe("Unicode Hardening - New Categories", () => {
  it("rejects tag characters when enabled", () => {
    withConfig({ rejectTagCharacters: true }, () => {
      const payload = "safe" + String.fromCodePoint(0xE0001) + "x";
      expect(() => normalizeInputString(payload, "tag-test")).toThrow(InvalidParameterError);
      try { normalizeInputString(payload, "tag-test"); } catch (e) {
        expect((e as Error).message).toContain("[code=ERR_UNICODE_TAG]");
      }
    });
  });

  it("rejects variation selectors when flag enabled", () => {
    withConfig({ rejectVariationSelectors: true }, () => {
      const payload = "A" + "\uFE0F"; // text variation selector
      expect(() => normalizeInputString(payload, "variation-test"))
        .toThrowError(/ERR_UNICODE_VARIATION/);
    });
  });

  it("soft allows PUA by default (no throw)", () => {
    const payload = "corp" + String.fromCharCode(0xE010) + "id"; // BMP PUA range
    const result = normalizeInputString(payload, "pua-soft");
    expect(result).toBe(payload.normalize("NFKC"));
  });

  it("can hard reject PUA when configured", () => {
    withConfig({ rejectPrivateUseArea: true }, () => {
      const payload = "corp" + String.fromCharCode(0xE010) + "id";
      expect(() => normalizeInputString(payload, "pua-hard"))
        .toThrowError(/ERR_UNICODE_PUA/);
    });
  });

  it("logs math styles but does not reject (soft flag)", () => {
    const frakturA = String.fromCodePoint(0x1D504); // Fraktur A
    const payload = "User" + frakturA;
    const out = normalizeInputString(payload, "math-style");
    expect(out).toContain(frakturA.normalize("NFKC"));
  });

  it("analyzeUnicodeString reports category presence", () => {
    const tag = String.fromCodePoint(0xE0001);
    const vs = "\uFE0F";
    const frakturA = String.fromCodePoint(0x1D504);
    const enclosed = String.fromCodePoint(0x2460); // circled 1
    const sample = "base" + tag + vs + frakturA + enclosed;
    const diag = analyzeUnicodeString(sample);
    expect(diag.contains.tag).toBe(true);
    expect(diag.contains.variation).toBe(true);
    expect(diag.contains.math).toBe(true);
    expect(diag.contains.enclosed).toBe(true);
    expect(diag.risk.metrics.some(m => m.id === "tagCharacters" && m.triggered)).toBe(true);
  });

  it("structured error codes propagate for bidi", () => {
    const payload = "abc\u202Edef"; // RLO
    expect(() => normalizeInputString(payload, "bidi-test"))
      .toThrowError(/ERR_UNICODE_BIDI/);
  });
});
