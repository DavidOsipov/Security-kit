import { describe, it, expect } from "vitest";
import { createSecureURL, normalizeOrigin, validateURL } from "../../src/url";
import { setUrlHardeningConfig } from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

// Minimal IDNA stub for tests: converts non-ASCII to punycode-like placeholder to assert codepath.
const testIdnaProvider = {
  toASCII(input: string): string {
    const labels = input.split(".");
    const mapped = labels
      .map((label) => {
        let out = label
          .toLowerCase()
          // drop spaces/controls and punctuation except hyphen
          .replace(/[^a-z0-9-]/g, "");
        out = out.replace(/^-+|-+$/g, "");
        if (out.length === 0) out = "x";
        return out;
      })
      .join(".");
    return mapped;
  },
} as const;

describe("URL hardening: bidi, traversal, UTS#46, IDNA, IPv4", () => {
  it("rejects bidi control characters in hostname", () => {
    expect(() => normalizeOrigin("https://ex\u202Eample.com")).toThrow(
      InvalidParameterError,
    );
  });

  it("detects path traversal in raw input when allowPaths", () => {
    const bad = () =>
      createSecureURL("https://example.com", ["a", "..", "b"]);
    expect(bad).toThrow(InvalidParameterError);
  });

  it("enforces UTS#46 hyphen rule (no ab--)", () => {
    expect(() => normalizeOrigin("https://ab--label.example")).toThrow(
      InvalidParameterError,
    );
  });

  it("applies IDNA conversion when enabled and provider set", () => {
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: testIdnaProvider });
    const url = normalizeOrigin("https://пример.рф");
    // Expect ASCII-only hostname due to provider conversion
    const hostname = new URL(url).hostname;
    expect(/^[\x00-\x7F]+$/.test(hostname)).toBe(true);
  });

  it("rejects ambiguous numeric dotted hosts (IPv4 shorthand)", () => {
    // strictIPv4AmbiguityChecks is enabled by default in production; enable here explicitly
    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: true });
    expect(() => normalizeOrigin("https://192.168.1"))
      .toThrow(InvalidParameterError);
    expect(() => normalizeOrigin("https://001.2.3.4"))
      .toThrow(InvalidParameterError);
    // Valid dotted-quad passes
    expect(() => normalizeOrigin("https://192.168.1.10")).not.toThrow();
  });

  it("immutable rebuild preserves query and fragment with encoding", () => {
    const href = createSecureURL(
      "https://example.com/base",
      ["child"],
      { q: "a b" },
      "frag value",
    );
    expect(href).toContain("/base/child?");
    const u = new URL(href);
    expect(u.searchParams.get("q")).toBe("a b");
    expect(href.endsWith("#frag%20value")).toBe(true);
  });
});

// Ensure config does not leak across other tests in the suite
import { afterAll } from "vitest";
afterAll(() => {
  setUrlHardeningConfig({ enableIdnaToAscii: false });
});
