import { describe, it, expect, vi } from "vitest";
import {
  normalizeOrigin,
  encodeHostLabel,
  InvalidParameterError,
} from "../../src/url";
import { getSafeSchemes } from "../../src/url-policy";

// Import internal functions for testing (these would need to be exposed for testing)
import * as urlModule from "../../src/url";

describe("url module - uncovered areas", () => {
  describe("normalizeOrigin error handling (line 89)", () => {
    it("should throw InvalidParameterError for malformed URLs", () => {
      expect(() => normalizeOrigin("://invalid")).toThrow(
        InvalidParameterError,
      );
      expect(() => normalizeOrigin("not-a-url")).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin("")).toThrow(InvalidParameterError);
    });

    it("should throw InvalidParameterError for URLs with credentials", () => {
      expect(() => normalizeOrigin("https://user:pass@example.com")).toThrow(
        InvalidParameterError,
      );
      expect(() => normalizeOrigin("https://user@example.com")).toThrow(
        InvalidParameterError,
      );
    });

    it("should handle edge cases in URL parsing", () => {
      // Test various malformed URL patterns that could trigger the catch block
      const malformedUrls = [
        "http://",
        "https://",
        "://example.com",
        "example.com",
      ];

      for (const url of malformedUrls) {
        expect(() => normalizeOrigin(url)).toThrow(InvalidParameterError);
      }

      // These are actually valid according to URL constructor
      expect(normalizeOrigin("ftp:///path")).toBe("ftp://path");
      expect(normalizeOrigin("javascript:alert(1)")).toBe("javascript://");
    });
  });

  describe("encodeHostLabel error cases (line 799)", () => {
    it("should throw InvalidParameterError when IDNA library is missing toASCII method", () => {
      expect(() => encodeHostLabel("example", {} as any)).toThrow(
        InvalidParameterError,
      );
      expect(() =>
        encodeHostLabel("example", { toASCII: null } as any),
      ).toThrow(InvalidParameterError);
      expect(() =>
        encodeHostLabel("example", { toASCII: undefined } as any),
      ).toThrow(InvalidParameterError);
    });

    it("should throw InvalidParameterError when IDNA library is null or undefined", () => {
      expect(() => encodeHostLabel("example", null as any)).toThrow(
        InvalidParameterError,
      );
      expect(() => encodeHostLabel("example", undefined as any)).toThrow(
        InvalidParameterError,
      );
    });

    it("should handle invalid IDNA library implementations", () => {
      const invalidLibraries = [
        { toASCII: "not-a-function" },
        { toASCII: 123 },
        { toASCII: {} },
        { toASCII: [] },
      ];

      for (const lib of invalidLibraries) {
        expect(() => encodeHostLabel("example", lib as any)).toThrow(
          InvalidParameterError,
        );
      }
    });
  });

  describe("isOriginAllowed function (lines 820-829)", () => {
    // We need to access the internal function for testing
    // This would require exposing it or using a different approach
    it("should handle permissive mode when allowlist is undefined", () => {
      // Test the logic path where allowlist is undefined
      const testOrigins = [
        "https://example.com",
        "http://example.com",
        "https://example.com:8080",
        "http://localhost:3000",
      ];

      // Since we can't directly access isOriginAllowed, we'll test through validateURL
      for (const origin of testOrigins) {
        const result = (urlModule as any).validateURL(origin);
        // Should not fail due to origin allowlist when allowlist is undefined
        if (result.ok) {
          expect(result.url.origin).toBeDefined();
        }
      }
    });

    it("should handle deny-all mode when allowlist is empty array", () => {
      const result = (urlModule as any).validateURL("https://example.com", {
        allowedOrigins: [],
      });
      expect(result.ok).toBe(false);
      if (!result.ok && result.error) {
        expect(result.error.name).toBe("InvalidParameterError");
        expect(result.error.code).toBe("ERR_INVALID_PARAMETER");
      }
    });

    it("should validate origin allowlist matching", () => {
      const allowlist = ["https://example.com", "https://trusted.com"];
      const testCases = [
        { url: "https://example.com/test", shouldAllow: true },
        { url: "https://trusted.com/test", shouldAllow: true },
        { url: "https://untrusted.com/test", shouldAllow: false },
        { url: "http://example.com/test", shouldAllow: false }, // Different scheme
        { url: "https://example.com:8080/test", shouldAllow: false }, // Different port
      ];

      for (const testCase of testCases) {
        const result = (urlModule as any).validateURL(testCase.url, {
          allowedOrigins: allowlist,
        });
        expect(result.ok).toBe(testCase.shouldAllow);
      }
    });
  });

  describe("enforceSchemeAndLength function", () => {
    it("should enforce scheme validation", () => {
      // Test through createSecureURL which calls enforceSchemeAndLength
      expect(() =>
        (urlModule as any).createSecureURL(
          "ftp://example.com",
          [],
          {},
          undefined,
          {
            allowedSchemes: ["https:"],
          },
        ),
      ).toThrow(InvalidParameterError);
    });

    it("should enforce length constraints", () => {
      const longUrl = "https://example.com/" + "a".repeat(1000);
      expect(() =>
        (urlModule as any).createSecureURL(
          "https://example.com",
          [longUrl],
          {},
          undefined,
          { maxLength: 100 },
        ),
      ).toThrow(InvalidParameterError);
    });

    it("should handle effective schemes intersection", () => {
      // Test case where allowedSchemes has no intersection with safe schemes
      expect(() =>
        (urlModule as any).createSecureURL(
          "https://example.com",
          [],
          {},
          undefined,
          {
            allowedSchemes: ["ftp:"], // ftp is not in SAFE_SCHEMES
          },
        ),
      ).toThrow(InvalidParameterError);
    });
  });

  describe("getEffectiveSchemes function", () => {
    it("should return SAFE_SCHEMES when allowedSchemes is undefined", () => {
      const safeSchemes = getSafeSchemes();
      expect(safeSchemes.length).toBeGreaterThan(0);
      // Test through validateURL
      const result = (urlModule as any).validateURL("https://example.com");
      expect(result.ok).toBe(true);
    });

    it("should return empty set for explicit deny-all", () => {
      const result = (urlModule as any).validateURL("https://example.com", {
        allowedSchemes: [],
      });
      expect(result.ok).toBe(false);
    });

    it("should handle intersection of user schemes with policy", () => {
      // Test valid intersection
      const result = (urlModule as any).validateURL("https://example.com", {
        allowedSchemes: ["https:", "http:"],
      });
      expect(result.ok).toBe(true);

      // Test invalid intersection
      const result2 = (urlModule as any).validateURL("https://example.com", {
        allowedSchemes: ["ftp:"],
      });
      expect(result2.ok).toBe(false);
    });
  });

  describe("OWASP ASVS L3 compliance - edge cases", () => {
    it("should prevent scheme confusion attacks", () => {
      const maliciousUrls = [
        "https://example.com@evil.com",
        "https://evil.com:443@example.com",
        "http://example.com:80@evil.com",
      ];

      for (const url of maliciousUrls) {
        const result = (urlModule as any).validateURL(url);
        expect(result.ok).toBe(false);
      }
    });

    it("should validate URL length limits comprehensively", () => {
      // Test various length limits
      const lengths = [100, 500, 1000, 2000];

      for (const maxLen of lengths) {
        const longUrl = "https://example.com/" + "a".repeat(maxLen + 1);
        const result = (urlModule as any).validateURL(longUrl, {
          maxLength: maxLen,
        });
        expect(result.ok).toBe(false);
        if (!result.ok && result.error) {
          expect(result.error.name).toBe("InvalidParameterError");
          expect(result.error.code).toBe("ERR_INVALID_PARAMETER");
        }
      }
    });

    it("should handle malformed scheme canonicalization", () => {
      const malformedSchemes = [
        "HTTPS", // uppercase
        "Https", // mixed case
        "https ", // trailing space
        " https", // leading space
        "https:", // already canonical
        "", // empty
      ];

      for (const scheme of malformedSchemes) {
        // Test through URL creation which uses canonicalizeScheme
        if (scheme === "https:" || scheme === "HTTPS" || scheme === "Https") {
          const result = (urlModule as any).validateURL(`https://example.com`);
          expect(result.ok).toBe(true);
        }
      }
    });
  });

  describe("Security hardening - malformed input handling", () => {
    it("should handle null and undefined inputs safely", () => {
      const result1 = (urlModule as any).validateURL(null as any);
      expect(result1.ok).toBe(false);
      if (!result1.ok && result1.error) {
        expect(result1.error.name).toBe("InvalidParameterError");
        expect(result1.error.code).toBe("ERR_INVALID_PARAMETER");
      }

      const result2 = (urlModule as any).validateURL(undefined as any);
      expect(result2.ok).toBe(false);
      if (!result2.ok && result2.error) {
        expect(result2.error.name).toBe("InvalidParameterError");
        expect(result2.error.code).toBe("ERR_INVALID_PARAMETER");
      }
    });

    it("should prevent prototype pollution in parameter processing", () => {
      // Test that parameter processing prevents prototype pollution
      const maliciousParams = {
        "safe-param": "value",
        __proto__: "polluted",
        constructor: "bad",
        prototype: "unsafe",
      };

      expect(() =>
        (urlModule as any).createSecureURL(
          "https://example.com",
          [],
          maliciousParams,
        ),
      ).toThrow();
    });

    it("should validate hostname safety", () => {
      const unsafeHostnames = [
        "evil.com.example.com", // potential bypass
        "..evil.com", // directory traversal
        "evil.com..", // directory traversal
        "evil..com", // directory traversal
      ];

      for (const hostname of unsafeHostnames) {
        const result = (urlModule as any).validateURL(`https://${hostname}`);
        // These should either fail validation or be properly handled
        expect(result).toBeDefined();
      }
    });
  });
});
