import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createSecureURL, normalizeOrigin, validateURL } from "../../src/url";
import {
  setUrlHardeningConfig,
  runWithStrictUrlHardening,
  _resetUrlPolicyForTests,
} from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

// Minimal IDNA stub for tests: maps non-ASCII to ASCII-like to assert Option B path
const idnaStub = {
  toASCII(input: string): string {
    // very simple mapping: drop non a-z0-9- chars per label, lowercased, ensure non-empty with 'x'
    return input
      .split(".")
      .map((label) => {
        let out = label.toLowerCase().replace(/[^a-z0-9-]/g, "");
        out = out.replace(/^-+|-+$/g, "");
        return out.length === 0 ? "x" : out;
      })
      .join(".");
  },
} as const;

describe("URL adversarial: Bidi controls and IDNA Option B", () => {
  beforeEach(() => {
    _resetUrlPolicyForTests();
  });

  afterEach(() => {
    // Ensure config does not leak between tests
    _resetUrlPolicyForTests();
  });

  describe("Bidi control characters in authority/hostname", () => {
    it("rejects RLO (\u202E) in hostname across APIs", () => {
      const evil = "https://ex\u202Eample.com";
      expect(() => createSecureURL(evil)).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin(evil)).toThrow(InvalidParameterError);
      const res = validateURL(evil);
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
    });

    it("rejects LRE (\u202A) and PDF (\u202C) when strict hardening is enabled", () => {
      runWithStrictUrlHardening(() => {
        const evil = "https://\u202Aexample\u202C.com";
        expect(() => createSecureURL(evil)).toThrow(InvalidParameterError);
        expect(() => normalizeOrigin(evil)).toThrow(InvalidParameterError);
        const res = validateURL(evil);
        expect(res.ok).toBe(false);
        if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
      });
    });
  });

  describe("IDNA Option B (toASCII) consistency across APIs", () => {
    it("rejects raw non-ASCII authority by default; allows when Option B enabled with provider", () => {
      const unicodeHost = "https://пример.рф";
      // Default behavior (Option B disabled): reject
      expect(() => createSecureURL(unicodeHost)).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin(unicodeHost)).toThrow(InvalidParameterError);
      const resDefault = validateURL(unicodeHost);
      expect(resDefault.ok).toBe(false);

      // Enable Option B with stub provider and verify ASCII mapping occurs consistently
      setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: idnaStub });
      const href = createSecureURL(unicodeHost);
      const norm = normalizeOrigin(unicodeHost);
      const res = validateURL(unicodeHost);
      expect(res.ok).toBe(true);
      if (res.ok) {
        // Hostname should be ASCII-only
        expect(/^[\x00-\x7F]+$/.test(new URL(href).hostname)).toBe(true);
        expect(/^[\x00-\x7F]+$/.test(new URL(norm).hostname)).toBe(true);
        expect(/^[\x00-\x7F]+$/.test(res.url.hostname)).toBe(true);
      }
    });

    it("still rejects Bidi controls even with IDNA enabled", () => {
      setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: idnaStub });
      const evil = "https://ex\u202Eample.com";
      expect(() => createSecureURL(evil)).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin(evil)).toThrow(InvalidParameterError);
      const res = validateURL(evil);
      expect(res.ok).toBe(false);
    });
  });
});
