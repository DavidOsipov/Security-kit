import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  parseURLParams,
  normalizeOrigin,
  encodeComponentRFC3986,
  strictDecodeURIComponent,
  strictDecodeURIComponentOrThrow,
} from "../../src/url";

describe("boundary and edge case tests", () => {
  describe("resource limits", () => {
    describe("URL length limits", () => {
      it("should handle maximum URL length", () => {
        const maxLength = 2048;
        const longPath = "a".repeat(maxLength - 20); // Leave room for protocol/host
        const url = `https://example.com/${longPath}`;

        const result = validateURL(url, { maxLength });
        expect(result.ok).toBe(true);
      });

      it("should reject URLs exceeding maxLength", () => {
        const url = "https://example.com/" + "a".repeat(2000);
        const result = validateURL(url, { maxLength: 100 });
        expect(result.ok).toBe(false);
      });

      it("should handle edge case of exact maxLength", () => {
        const url = "https://example.com/test";
        const result = validateURL(url, { maxLength: url.length });
        expect(result.ok).toBe(true);
      });

      it("should handle very short maxLength", () => {
        const result = validateURL("https://example.com", { maxLength: 5 });
        expect(result.ok).toBe(false);
      });
    });

    describe("path segment limits", () => {
      it("should handle maximum path segments", () => {
        const segments = Array.from({ length: 64 }, (_, i) => `seg${i}`);
        const result = createSecureURL("https://example.com", segments);
        expect(result).toBe(`https://example.com/${segments.join("/")}`);
      });

      it("should reject too many path segments", () => {
        const segments = Array.from({ length: 70 }, (_, i) => `seg${i}`);
        expect(() =>
          createSecureURL("https://example.com", segments),
        ).toThrow();
      });

      it("should reject empty path segments", () => {
        expect(() => createSecureURL("https://example.com", [""])).toThrow();
      });
    });

    describe("query parameter limits", () => {
      it("should handle maximum query parameters", () => {
        const params: Record<string, unknown> = {};
        for (let i = 0; i < 256; i++) params[`param${i}`] = `value${i}`;

        const result = createSecureURL("https://example.com", [], params);
        expect(result.startsWith("https://example.com/?")).toBe(true);
      });

      it("should reject too many query parameters", () => {
        const params: Record<string, unknown> = {};
        for (let i = 0; i < 300; i++) params[`param${i}`] = `value${i}`;

        expect(() =>
          createSecureURL("https://example.com", [], params),
        ).toThrow();
      });

      it("should handle parameters with very long values", () => {
        const longValue = "a".repeat(1000);
        const result = createSecureURL("https://example.com", [], {
          test: longValue,
        });
        expect(result).toBe(
          `https://example.com/?test=${encodeURIComponent(longValue)}`,
        );
      });

      it("should handle parameters with very long keys", () => {
        const longKey = "a".repeat(128);
        const result = createSecureURL("https://example.com", [], {
          [longKey]: "value",
        });
        expect(result).toBe(
          `https://example.com/?${encodeURIComponent(longKey)}=value`,
        );
      });
    });

    describe("hostname length limits", () => {
      it("should handle maximum FQDN length", () => {
        const longLabel = "a".repeat(63);
        const hostname = `${longLabel}.example.com`;
        const result = validateURL(`https://${hostname}`);
        expect(result.ok).toBe(true);
      });

      it("should reject FQDN exceeding maximum length", () => {
        const longHostname = "a".repeat(254) + ".com";
        const result = validateURL(`https://${longHostname}`);
        expect(result.ok).toBe(false);
      });

      it("should handle hostname with maximum label length", () => {
        const maxLabel = "a".repeat(63);
        const result = validateURL(`https://${maxLabel}.com`);
        expect(result.ok).toBe(true);
      });

      it("should reject hostname label exceeding maximum length", () => {
        const longLabel = "a".repeat(64);
        const result = validateURL(`https://${longLabel}.com`);
        expect(result.ok).toBe(false);
      });
    });
  });

  describe("error handling edge cases", () => {
    describe("null and undefined inputs", () => {
      it("should handle null base URL", () => {
        expect(() => createSecureURL(null as any)).toThrow();
      });

      it("should handle undefined base URL", () => {
        expect(() => createSecureURL(undefined as any)).toThrow();
      });

      it("should handle null path segments", () => {
        expect(() =>
          createSecureURL("https://example.com", null as any),
        ).toThrow();
      });

      it("should handle undefined path segments", () => {
        const result = createSecureURL("https://example.com", undefined);
        expect(result).toBe("https://example.com/");
      });

      it("should handle null query parameters", () => {
        expect(() =>
          createSecureURL("https://example.com", [], null as any),
        ).toThrow();
      });

      it("should handle undefined query parameters", () => {
        const result = createSecureURL("https://example.com", [], undefined);
        expect(result).toBe("https://example.com/");
      });

      it("should handle null fragment", () => {
        expect(() =>
          createSecureURL("https://example.com", [], {}, null as any),
        ).toThrow();
      });
    });

    describe("type coercion edge cases", () => {
      it("should handle number base URL", () => {
        expect(() => createSecureURL(123 as any)).toThrow();
      });

      it("should handle boolean base URL", () => {
        expect(() => createSecureURL(true as any)).toThrow();
      });

      it("should handle object base URL", () => {
        expect(() => createSecureURL({} as any)).toThrow();
      });

      it("should handle array base URL", () => {
        expect(() => createSecureURL([] as any)).toThrow();
      });

      it("should handle number path segments", () => {
        expect(() =>
          createSecureURL("https://example.com", 123 as any),
        ).toThrow();
      });

      it("should handle string path segments", () => {
        expect(() =>
          createSecureURL("https://example.com", "invalid" as any),
        ).toThrow();
      });
    });

    describe("malformed input edge cases", () => {
      it("should handle empty string inputs", () => {
        expect(() => createSecureURL("")).toThrow();
        expect(() => normalizeOrigin("")).toThrow();
      });

      it("should handle whitespace-only inputs", () => {
        expect(() => createSecureURL("   ")).toThrow();
        expect(() => normalizeOrigin("   ")).toThrow();
      });

      it("should handle URLs with only protocol", () => {
        const result = validateURL("https:");
        expect(result.ok).toBe(false);
      });

      it("should handle URLs with invalid protocol", () => {
        const result = validateURL("invalid://example.com");
        expect(result.ok).toBe(false);
      });

      it("should handle URLs with invalid hostname", () => {
        const result = validateURL("https://");
        expect(result.ok).toBe(false);
      });
    });
  });

  describe("Unicode and encoding edge cases", () => {
    describe("Unicode normalization", () => {
      it("should handle various Unicode normalization forms", () => {
        // Test different normalization forms of the same character
        const nfc = "café"; // NFC form
        const nfd = "café"; // NFD form (decomposed)
        const nfkc = "café"; // NFKC form
        const nfkd = "café"; // NFKD form

        const result1 = createSecureURL("https://example.com", [nfc]);
        const result2 = createSecureURL("https://example.com", [nfd]);
        const result3 = createSecureURL("https://example.com", [nfkc]);
        const result4 = createSecureURL("https://example.com", [nfkd]);

        // All should normalize to the same encoded result
        expect(result1).toBe(result2);
        expect(result2).toBe(result3);
        expect(result3).toBe(result4);
      });

      it("should handle zero-width characters", () => {
        const zeroWidth = "test\u200B\u200C\u200D\uFEFF"; // Various zero-width chars
        const result = createSecureURL("https://example.com", [zeroWidth]);
        expect(result).toBe(
          "https://example.com/test%E2%80%8B%E2%80%8C%E2%80%8D%EF%BB%BF",
        );
      });

      it("should handle Unicode control characters", () => {
        const controlChars = "test\u0000\u0001\u001F"; // Null, SOH, US
        expect(() =>
          createSecureURL("https://example.com", [controlChars]),
        ).toThrow();
      });

      it("should handle Unicode non-characters", () => {
        const nonChar = "test\uFFFF"; // Non-character
        const result = createSecureURL("https://example.com", [nonChar]);
        expect(result).toBe("https://example.com/test%EF%BF%BF");
      });
    });

    describe("percent encoding edge cases", () => {
      it("should handle already percent-encoded input", () => {
        const result = createSecureURL("https://example.com", [
          "path%20with%20spaces",
        ]);
        expect(result).toBe("https://example.com/path%2520with%2520spaces"); // Double-encoded
      });

      it("should treat already-encoded input as literal and double-encode", () => {
        const result = createSecureURL("https://example.com", [
          "path with%20spaces",
        ]);
        // Implementation encodes raw spaces and percent signs in the segment;
        // an input containing '%20' will result in '%2520' in the URL (double-encoded).
        expect(result).toBe("https://example.com/path%20with%2520spaces");
      });

      it("should handle invalid percent encoding", () => {
        const result = validateURL("https://example.com/path%2");
        expect(result.ok).toBe(false);
      });

      it("should handle percent encoding of special characters", () => {
        expect(() =>
          createSecureURL("https://example.com", [
            "path/with?query=value#fragment",
          ]),
        ).toThrow();
      });

      it("should handle over-encoded sequences", () => {
        const result = validateURL("https://example.com/%25%32%30"); // %2520 = %20 encoded
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/%25%32%30");
        }
      });
    });

    describe("IDNA and international domain names", () => {
      it("should handle IDNA-encoded domains", () => {
        const result = validateURL("https://xn--caf-dma.com"); // café.com in IDNA
        expect(result.ok).toBe(true);
      });

      it("should reject raw Unicode domains (require IDNA/punycode)", () => {
        const result = validateURL("https://café.com");
        expect(result.ok).toBe(false);
      });

      it("should reject mixed ASCII and Unicode domains (require IDNA)", () => {
        const result = validateURL("https://test.café.com");
        expect(result.ok).toBe(false);
      });
    });
  });

  describe("protocol and scheme edge cases", () => {
    describe("case variations", () => {
      it("should handle uppercase protocol", () => {
        const result = validateURL("HTTPS://example.com");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.protocol).toBe("https:");
        }
      });

      it("should handle mixed case protocol", () => {
        const result = validateURL("HttPs://example.com");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.protocol).toBe("https:");
        }
      });

      it("should handle protocol without trailing colon in input", () => {
        // This tests internal canonicalization
        const result = validateURL("https://example.com");
        expect(result.ok).toBe(true);
      });
    });

    describe("default ports", () => {
      it("should handle explicit default ports", () => {
        const result1 = normalizeOrigin("https://example.com:443");
        const result2 = normalizeOrigin("https://example.com");
        expect(result1).toBe(result2);
      });

      it("should preserve non-default ports", () => {
        const result = normalizeOrigin("https://example.com:8443");
        expect(result).toBe("https://example.com:8443");
      });

      it("should handle HTTP default port", () => {
        const result1 = normalizeOrigin("http://example.com:80");
        const result2 = normalizeOrigin("http://example.com");
        expect(result1).toBe(result2);
      });
    });

    describe("scheme restrictions", () => {
      it("should reject unknown schemes", () => {
        const result = validateURL("unknown://example.com");
        expect(result.ok).toBe(false);
      });

      it("should reject mailto scheme even when caller permits it by default (strict mode)", () => {
        const result = validateURL("mailto:test@example.com", {
          allowedSchemes: ["mailto:"],
        });
        // Strict default: disallow when no intersection with SAFE_SCHEMES unless runtime policy toggled
        expect(result.ok).toBe(false);
      });

      it("should reject mailto scheme by default", () => {
        const result = validateURL("mailto:test@example.com");
        expect(result.ok).toBe(false);
      });
    });
  });

  describe("parsing and validation edge cases", () => {
    describe("URL component boundaries", () => {
      it("should handle URLs with only hostname", () => {
        const result = validateURL("https://example.com");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/");
          expect(result.url.search).toBe("");
          expect(result.url.hash).toBe("");
        }
      });

      it("should handle URLs with only path", () => {
        const result = validateURL("https://example.com/path");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/path");
        }
      });

      it("should handle URLs with query only", () => {
        const result = validateURL("https://example.com?query=value");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.search).toBe("?query=value");
        }
      });

      it("should handle URLs with fragment only", () => {
        const result = validateURL("https://example.com#fragment");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.hash).toBe("#fragment");
        }
      });

      it("should handle URLs with all components", () => {
        const result = validateURL(
          "https://example.com:8080/path/to/resource?query=value&other=test#fragment",
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.protocol).toBe("https:");
          expect(result.url.hostname).toBe("example.com");
          expect(result.url.port).toBe("8080");
          expect(result.url.pathname).toBe("/path/to/resource");
          expect(result.url.search).toBe("?query=value&other=test");
          expect(result.url.hash).toBe("#fragment");
        }
      });
    });

    describe("special hostname formats", () => {
      it("should handle localhost", () => {
        const result = validateURL("https://localhost");
        expect(result.ok).toBe(true);
      });

      it("should handle IPv4 addresses", () => {
        const result = validateURL("https://192.168.1.1");
        expect(result.ok).toBe(true);
      });

      it("should handle IPv6 addresses", () => {
        const result = validateURL("https://[::1]");
        expect(result.ok).toBe(true);
      });

      it("should handle IPv6 with port", () => {
        const result = validateURL("https://[::1]:8080");
        expect(result.ok).toBe(true);
      });

      it("should reject invalid IPv4", () => {
        const result = validateURL("https://256.1.1.1");
        expect(result.ok).toBe(false);
      });

      it("should reject invalid IPv6", () => {
        const result = validateURL("https://[invalid]");
        expect(result.ok).toBe(false);
      });
    });

    describe("path handling", () => {
      it("should handle root path", () => {
        const result = validateURL("https://example.com/");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/");
        }
      });

      it("should handle relative paths", () => {
        const result = validateURL(
          "https://example.com/path/./subpath/../other",
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/path/other");
        }
      });

      it("should handle encoded paths", () => {
        const result = validateURL("https://example.com/path%20with%20spaces");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/path%20with%20spaces");
        }
      });

      it("should handle empty path segments", () => {
        const result = validateURL("https://example.com/path//to");
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.url.pathname).toBe("/path//to");
        }
      });
    });

    describe("query parameter edge cases", () => {
      it("should handle empty query values", () => {
        const result = parseURLParams("https://example.com?empty=");
        expect(result).toEqual({ empty: "" });
      });

      it("should handle query without equals", () => {
        const result = parseURLParams("https://example.com?flag");
        expect(result).toEqual({ flag: "" });
      });

      it("should handle multiple equals in query", () => {
        const result = parseURLParams("https://example.com?key=value=another");
        expect(result).toEqual({ key: "value=another" });
      });

      it("should handle plus signs in query", () => {
        const result = parseURLParams("https://example.com?q=test+value");
        expect(result).toEqual({ q: "test value" });
      });

      it("should handle encoded plus signs in query", () => {
        const result = parseURLParams("https://example.com?q=test%2Bvalue");
        expect(result).toEqual({ q: "test+value" });
      });
    });
  });

  describe("encoding function edge cases", () => {
    describe("encodeComponentRFC3986", () => {
      it("should handle empty input", () => {
        const result = encodeComponentRFC3986("");
        expect(result).toBe("");
      });

      it("should handle already encoded input", () => {
        const result = encodeComponentRFC3986("test%20value");
        expect(result).toBe("test%2520value");
      });

      it("should handle special characters", () => {
        const result = encodeComponentRFC3986(
          "test@example.com?query=value#fragment",
        );
        expect(result).toBe("test%40example.com%3Fquery%3Dvalue%23fragment");
      });

      it("should handle Unicode characters", () => {
        const result = encodeComponentRFC3986("café");
        expect(result).toBe("caf%C3%A9");
      });

      it("should handle control characters", () => {
        expect(() => encodeComponentRFC3986("test\x00")).toThrow();
      });

      it("should handle null input", () => {
        const result = encodeComponentRFC3986(null);
        expect(result).toBe("");
      });

      it("should handle undefined input", () => {
        const result = encodeComponentRFC3986(undefined);
        expect(result).toBe("");
      });
    });

    describe("strictDecodeURIComponent", () => {
      it("should handle empty input", () => {
        const result = strictDecodeURIComponent("");
        expect(result.ok).toBe(true);
        if (!result.ok) throw result.error;
        expect(result.value).toBe("");
      });

      it("should handle already decoded input", () => {
        const result = strictDecodeURIComponent("test value");
        expect(result.ok).toBe(true);
        if (!result.ok) throw result.error;
        expect(result.value).toBe("test value");
      });

      it("should handle double encoded input", () => {
        const result = strictDecodeURIComponent("test%2520value");
        expect(result.ok).toBe(true);
        if (!result.ok) throw result.error;
        expect(result.value).toBe("test%20value");
      });

      it("should handle invalid encoding", () => {
        const result = strictDecodeURIComponent("test%2");
        expect(result.ok).toBe(false);
      });

      it("should handle control characters in decoded result", () => {
        const result = strictDecodeURIComponent("%00");
        expect(result.ok).toBe(false);
      });

      it("should handle too long input", () => {
        const longInput = "a".repeat(5000);
        const result = strictDecodeURIComponent(longInput);
        expect(result.ok).toBe(false);
      });

      it("should handle null bytes in encoding", () => {
        const result = strictDecodeURIComponent("%00test");
        expect(result.ok).toBe(false);
      });
    });

    describe("strictDecodeURIComponentOrThrow", () => {
      it("should decode valid input", () => {
        const result = strictDecodeURIComponentOrThrow("test%20value");
        expect(result).toBe("test value");
      });

      it("should throw on invalid input", () => {
        expect(() => strictDecodeURIComponentOrThrow("test%2")).toThrow();
      });

      it("should throw on control characters", () => {
        expect(() => strictDecodeURIComponentOrThrow("%00")).toThrow();
      });
    });
  });

  describe("origin normalization edge cases", () => {
    it("should handle origins with trailing slash", () => {
      const result = normalizeOrigin("https://example.com/");
      expect(result).toBe("https://example.com");
    });

    it("should handle origins with path", () => {
      expect(() => normalizeOrigin("https://example.com/path")).toThrow();
    });

    it("should handle origins with query", () => {
      expect(() =>
        normalizeOrigin("https://example.com?query=value"),
      ).toThrow();
    });

    it("should handle origins with fragment", () => {
      expect(() => normalizeOrigin("https://example.com#fragment")).toThrow();
    });

    it("should handle origins with user info", () => {
      expect(() => normalizeOrigin("https://user@example.com")).toThrow();
    });

    it("should handle origins with password", () => {
      expect(() => normalizeOrigin("https://user:pass@example.com")).toThrow();
    });

    it("should handle IPv6 origins", () => {
      const result = normalizeOrigin("https://[::1]");
      expect(result).toBe("https://[::1]");
    });

    it("should handle IPv6 origins with port", () => {
      const result = normalizeOrigin("https://[::1]:8080");
      expect(result).toBe("https://[::1]:8080");
    });
  });

  describe("concurrent and async edge cases", () => {
    it("should handle rapid successive calls", () => {
      // Test that internal state doesn't get corrupted with rapid calls
      const results = [];
      for (let i = 0; i < 100; i++) {
        results.push(validateURL(`https://example.com/path${i}`));
      }
      expect(results.every((r) => r.ok)).toBe(true);
    });

    it("should handle large batch processing", () => {
      const urls = Array.from(
        { length: 1000 },
        (_, i) => `https://example${i}.com`,
      );
      const results = urls.map((url) => validateURL(url));
      expect(results.every((r) => r.ok)).toBe(true);
    });
  });

  describe("memory and performance edge cases", () => {
    it("should handle deeply nested path structures", () => {
      const deepPath = Array.from({ length: 50 }, (_, i) => `level${i}`).join(
        "/",
      );
      const result = validateURL(`https://example.com/${deepPath}`);
      expect(result.ok).toBe(true);
    });

    it("should handle URLs with many query parameters", () => {
      const manyParams = Array.from(
        { length: 100 },
        (_, i) => `param${i}=value${i}`,
      ).join("&");
      const result = validateURL(`https://example.com?${manyParams}`);
      expect(result.ok).toBe(true);
    });

    it("should handle URLs with large fragments", () => {
      const largeFragment = "a".repeat(10000);
      const result = validateURL(`https://example.com#${largeFragment}`, {
        maxLength: 15000,
      });
      expect(result.ok).toBe(true);
    });
  });
});
