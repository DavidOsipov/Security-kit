import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  setUrlHardeningConfig,
  getUrlHardeningConfig,
  _resetUrlPolicyForTests,
} from "../../src/config";
import { createSecureURL, normalizeOrigin, validateURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

// A provider that returns non-ASCII: should be rejected by runtime conversion guard
const badNonAsciiProvider = {
  toASCII(input: string): string {
    return input + "é"; // inject a non-ASCII character
  },
} as const;

// A provider that returns control characters: should be rejected
const badControlProvider = {
  toASCII(input: string): string {
    return "bad\u0000host";
  },
} as const;

// A minimal good provider used for positive cases; strips non-LDH and lowercases
const goodProvider = {
  toASCII(input: string): string {
    return input
      .split(".")
      .map((label) =>
        label
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, "")
          .replace(/^-+|-+$/g, "") || "x",
      )
      .join(".");
  },
} as const;

describe("IDNA provider contract and runtime validation", () => {
  beforeEach(() => {
    _resetUrlPolicyForTests();
  });
  afterEach(() => {
    _resetUrlPolicyForTests();
    // Reset to defaults (Option B disabled) between tests
    setUrlHardeningConfig({ enableIdnaToAscii: false, idnaProvider: undefined });
  });

  it("rejects enabling Option B without provider", () => {
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true })).toThrow(
      InvalidParameterError,
    );
  });

  it("rejects provider with non-ASCII output at configuration time", () => {
    expect(() =>
      setUrlHardeningConfig({
        enableIdnaToAscii: true,
        idnaProvider: badNonAsciiProvider,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("rejects provider returning control characters at configuration time", () => {
    expect(() =>
      setUrlHardeningConfig({
        enableIdnaToAscii: true,
        idnaProvider: badControlProvider,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("accepts a well-behaved provider and yields ASCII-only hostnames across APIs", () => {
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: goodProvider });
    const unicodeHost = "https://пример.рф";
    const href = createSecureURL(unicodeHost);
    const norm = normalizeOrigin(unicodeHost);
    const res = validateURL(unicodeHost);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(/^[\x00-\x7F]+$/.test(new URL(href).hostname)).toBe(true);
      expect(/^[\x00-\x7F]+$/.test(new URL(norm).hostname)).toBe(true);
      expect(/^[\x00-\x7F]+$/.test(res.url.hostname)).toBe(true);
    }
  });
});
