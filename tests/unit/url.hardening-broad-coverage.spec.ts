import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  normalizeOrigin,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("URL hardening – broad coverage for new guards", () => {
  describe("normalizeOrigin strict origin form", () => {
    it("rejects non-root pathname", () => {
      expect(() => normalizeOrigin("https://example.com/path")).toThrow(
        InvalidParameterError,
      );
      expect(() => normalizeOrigin("https://example.com/a/b")).toThrow(
        InvalidParameterError,
      );
    });

    it("rejects query and fragment components", () => {
      expect(() => normalizeOrigin("https://example.com/?q=1")).toThrow(
        InvalidParameterError,
      );
      expect(() => normalizeOrigin("https://example.com/#x")).toThrow(
        InvalidParameterError,
      );
    });

    it("returns canonical origin without trailing slash", () => {
      const origin = normalizeOrigin("https://example.com/");
      expect(origin).toBe("https://example.com");
    });

    it("accepts bracketed IPv6 origins", () => {
      const origin = normalizeOrigin("https://[::1]/");
      expect(origin).toBe("https://[::1]");
    });
  });

  describe("fragment handling – strict vs non-strict", () => {
    it("strict fragment encoding uses RFC3986 and blocks dangerous content", () => {
      // strictFragment=true (default) should encode space as %20 and reject script-like content
      const href = createSecureURL(
        "https://example.com",
        ["child"],
        { a: "b" },
        "frag value",
        { strictFragment: true },
      );
      expect(href.endsWith("#frag%20value")).toBe(true);
      // Reject dangerous fragment
      expect(() =>
        createSecureURL("https://example.com", [], {}, "javascript:alert(1)")
      ).toThrow(InvalidParameterError);
    });

    it("non-strict fragment preserves reserved characters via encodeURI", () => {
      const href = createSecureURL(
        "https://example.com",
        [],
        {},
        "frag:val/ue?x=1&y=2",
        { strictFragment: false },
      );
      // encodeURI preserves ":/?#[]@!$&'()*+,;=" appropriately
      expect(href.includes("#frag:val/ue?x=1&y=2")).toBe(true);
    });
  });

  describe("validateURL hardened checks parity", () => {
    it("rejects malformed percent-encoding in pathname when enabled", () => {
      const result = validateURL("https://example.com/%GG", {
        // maxLength large to avoid length failure masking this check
        maxLength: 10000,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
        expect(result.error.message).toMatch(/pathname contains malformed percent-encoding/);
      }
    });

    it("rejects dangerous fragments in strict mode", () => {
      const result = validateURL("https://example.com/#javascript:alert(1)", {
        strictFragment: true,
        maxLength: 10000,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });
  });

  describe("query value percent-encoding and decoding parity", () => {
    it("updateURLParams rejects malformed percent-encoding in values parity with create", () => {
      // Start with simple URL
      const base = "https://example.com";
      // Malformed percent-encoding in update value should throw
      expect(() =>
        updateURLParams(base, { bad: "%G1" })
      ).toThrow(InvalidParameterError);

      // Also reject if decodeURIComponent would throw (e.g., stray %)
      expect(() =>
        updateURLParams(base, { bad: "%" })
      ).toThrow(InvalidParameterError);
    });
  });

  describe("IPv4 shorthand preservation with path & query", () => {
    it("rejects ambiguous IPv4 shorthand by default", () => {
      expect(() =>
        createSecureURL("https://192.168.1", ["a", "b"], { q: "1" }),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("additional hardened guards", () => {
    it("rejects encoded navigation in raw path segments", () => {
      expect(() => createSecureURL("https://example.com", ["%2f"]))
        .toThrow(InvalidParameterError);
      expect(() => createSecureURL("https://example.com", ["..%2e"]))
        .toThrow(InvalidParameterError);
    });

    it("validateURL permanently forbids dangerous schemes", () => {
      const res = validateURL("javascript:alert(1)");
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.error).toBeInstanceOf(InvalidParameterError);
        expect(String(res.error.message)).toMatch(/explicitly forbidden/i);
      }
    });
  });

  describe("double-encoding traversal & fragment carryover", () => {
    it("rejects double-encoded navigation sequences in segments (e.g., %252f, ..%252e)", () => {
      // %252f => first decode: %2f, second decode: '/'
      expect(() => createSecureURL("https://example.com", ["%252f"]))
        .toThrow(InvalidParameterError);
      // %255c => first decode: %5c, second decode: '\\'
      expect(() => createSecureURL("https://example.com", ["%255c"]))
        .toThrow(InvalidParameterError);
      // ..%252e => first decode: ..%2e, second decode would expose '..'
      expect(() => createSecureURL("https://example.com", ["..%252e"]))
        .toThrow(InvalidParameterError);
    });

    it("carries over base fragment when fragment arg is undefined (after validation)", () => {
      const href = createSecureURL("https://example.com/#frag");
      expect(href.endsWith("#frag")).toBe(true);
      expect(new URL(href).hash).toBe("#frag");
    });
  });
});
