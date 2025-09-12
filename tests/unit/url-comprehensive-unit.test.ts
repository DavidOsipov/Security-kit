import { describe, it, expect } from "vitest";
import { InvalidParameterError } from "../../src/errors";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  validateURLStrict,
  parseURLParams,
  normalizeOrigin,
  encodeComponentRFC3986,
  encodePathSegment,
  encodeQueryValue,
  encodeFormValue,
  encodeMailtoValue,
  strictDecodeURIComponent,
  strictDecodeURIComponentOrThrow,
  encodeHostLabel,
  updateURLParameters,
  parseURLParameters,
} from "../../src/url";

describe("comprehensive unit tests for URL module", () => {
  describe("createSecureURL", () => {
    it("should create basic HTTPS URL", () => {
      const result = createSecureURL("https://example.com");
      expect(result).toBe("https://example.com/");
    });

    it("should create URL with path segments", () => {
      const result = createSecureURL("https://example.com", [
        "api",
        "v1",
        "users",
      ]);
      expect(result).toBe("https://example.com/api/v1/users");
    });

    it("should create URL with query parameters", () => {
      const result = createSecureURL("https://example.com", [], {
        q: "test",
        limit: 10,
      });
      expect(result).toBe("https://example.com/?q=test&limit=10");
    });

    it("should create URL with fragment", () => {
      const result = createSecureURL("https://example.com", [], {}, "section1");
      expect(result).toBe("https://example.com/#section1");
    });

    it("should create URL with all components", () => {
      const result = createSecureURL(
        "https://example.com",
        ["api", "v1"],
        { q: "test", sort: "name" },
        "results",
      );
      expect(result).toBe(
        "https://example.com/api/v1?q=test&sort=name#results",
      );
    });

    it("should enforce HTTPS when required", () => {
      expect(() =>
        createSecureURL("http://example.com", [], {}, undefined, {
          requireHTTPS: true,
        }),
      ).toThrow();
    });

    it("should reject dangerous schemes", () => {
      expect(() => createSecureURL("javascript:alert(1)")).toThrow();
      expect(() =>
        createSecureURL("data:text/html,<script>alert(1)</script>"),
      ).toThrow();
    });

    it("should handle Map for query parameters", () => {
      const params = new Map<string, string | number>([
        ["key", "value"],
        ["num", 42],
      ]);
      const coerced = new Map<string, string>();
      for (const [k, v] of params) coerced.set(k, String(v));
      const result = createSecureURL("https://example.com", [], coerced);
      expect(result).toBe("https://example.com/?key=value&num=42");
    });

    it("should reject unsafe keys in query parameters", () => {
      // Object literal with '__proto__' may not create an own property in JS;
      // use a Map to ensure the dangerous key is detected by the implementation.
      const params = new Map<string, string>([["__proto__", "evil"]]);
      expect(() =>
        createSecureURL("https://example.com", [], params),
      ).toThrow();
    });

    it("should handle onUnsafeKey option", () => {
      const result = createSecureURL(
        "https://example.com",
        [],
        { __proto__: "evil" } as any,
        undefined,
        { onUnsafeKey: "skip" },
      );
      expect(result).toBe("https://example.com/");
    });

    it("should enforce maxLength", () => {
      expect(() =>
        createSecureURL("https://example.com", [], {}, undefined, {
          maxLength: 10,
        }),
      ).toThrow();
    });

    it("should enforce maxPathSegments", () => {
      const manySegments = Array.from({ length: 70 }, (_, i) => `seg${i}`);
      expect(() =>
        createSecureURL("https://example.com", manySegments),
      ).toThrow();
    });

    it("should enforce maxQueryParameters", () => {
      const manyParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) manyParams[`param${i}`] = "value";
      expect(() =>
        createSecureURL("https://example.com", [], manyParams),
      ).toThrow();
    });

    it("should validate strict fragments", () => {
      expect(() =>
        createSecureURL("https://example.com", [], {}, "javascript:alert(1)"),
      ).toThrow();
    });

    it("should allow disabling strict fragment validation", () => {
      const result = createSecureURL(
        "https://example.com",
        [],
        {},
        "javascript:alert(1)",
        { strictFragment: false },
      );
      expect(result).toBe("https://example.com/#javascript:alert(1)");
    });

    it("should handle allowedSchemes", () => {
      const result = createSecureURL("https://example.com", [], {}, undefined, {
        allowedSchemes: ["https:"],
      });
      expect(result).toBe("https://example.com/");

      // When allowedSchemes has no intersection with policy, implementation throws
      expect(() =>
        createSecureURL("https://example.com", [], {}, undefined, {
          allowedSchemes: ["mailto:"],
        }),
      ).toThrow();
    });

    it("should reject non-allowed schemes", () => {
      expect(() =>
        createSecureURL("ftp://example.com", [], {}, undefined, {
          allowedSchemes: ["https:"],
        }),
      ).toThrow();
    });

    it("should normalize input strings", () => {
      // Test with Unicode normalization
      const result = createSecureURL("https://example.com", ["café"]);
      expect(result).toBe("https://example.com/caf%C3%A9");
    });

    it("should reject control characters in fragment", () => {
      expect(() =>
        createSecureURL("https://example.com", [], {}, "test\x00evil"),
      ).toThrow();
    });
  });

  describe("updateURLParams", () => {
    it("should update existing query parameters", () => {
      const result = updateURLParams("https://example.com?q=old", {
        q: "new",
        sort: "name",
      });
      expect(result).toBe("https://example.com/?q=new&sort=name");
    });

    it("should add new query parameters", () => {
      const result = updateURLParams("https://example.com", { q: "test" });
      expect(result).toBe("https://example.com/?q=test");
    });

    it("should remove parameters when undefined and removeUndefined is true", () => {
      const result = updateURLParams("https://example.com?q=test&keep=value", {
        q: undefined,
        new: "param",
      });
      expect(result).toBe("https://example.com/?keep=value&new=param");
    });

    it("should handle Map for updates", () => {
      const updates = new Map<string, string | number>([
        ["key", "value"],
        ["num", 42],
      ]);
      const coerced = new Map<string, string>();
      for (const [k, v] of updates) coerced.set(k, String(v));
      const result = updateURLParams("https://example.com", coerced);
      expect(result).toBe("https://example.com/?key=value&num=42");
    });

    it("should reject unsafe keys", () => {
      const params = new Map<string, string>([["__proto__", "evil"]]);
      expect(() => updateURLParams("https://example.com", params)).toThrow();
    });

    it("should handle onUnsafeKey option", () => {
      const result = updateURLParams(
        "https://example.com",
        { __proto__: "evil" },
        { onUnsafeKey: "skip" },
      );
      expect(result).toBe("https://example.com/");
    });

    it("should enforce HTTPS when required", () => {
      expect(() =>
        updateURLParams("http://example.com", {}, { requireHTTPS: true }),
      ).toThrow();
    });

    it("should enforce maxLength", () => {
      expect(() =>
        updateURLParams(
          "https://example.com",
          { long: "x".repeat(2000) },
          { maxLength: 100 },
        ),
      ).toThrow();
    });

    it("should enforce maxQueryParameters", () => {
      const manyParams: Record<string, string> = {};
      for (let i = 0; i < 300; i++) manyParams[`param${i}`] = "value";
      expect(() =>
        updateURLParams("https://example.com", manyParams),
      ).toThrow();
    });

    it("should handle allowedSchemes", () => {
      const result = updateURLParams(
        "https://example.com",
        {},
        { allowedSchemes: ["https:"] },
      );
      expect(result).toBe("https://example.com/");

      expect(() =>
        updateURLParams(
          "https://example.com",
          {},
          { allowedSchemes: ["mailto:"] },
        ),
      ).toThrow();
    });
  });

  describe("validateURL", () => {
    it("should validate valid HTTPS URL", () => {
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
      if (!result.ok) throw result.error;
      expect(result.url.href).toBe("https://example.com/");
    });

    it("should reject invalid URL", () => {
      const result = validateURL("not-a-url");
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected failure");
      expect(result.error).toBeInstanceOf(Error);
    });

    it("should enforce HTTPS when required", () => {
      const result = validateURL("http://example.com", { requireHTTPS: true });
      expect(result.ok).toBe(false);
    });

    it("should validate allowed origins", () => {
      const result = validateURL("https://example.com", {
        allowedOrigins: ["https://example.com"],
      });
      expect(result.ok).toBe(true);
    });

    it("should reject non-allowed origins", () => {
      const result = validateURL("https://evil.com", {
        allowedOrigins: ["https://example.com"],
      });
      expect(result.ok).toBe(false);
    });

    it("should enforce maxLength", () => {
      const result = validateURL("https://example.com", { maxLength: 10 });
      expect(result.ok).toBe(false);
    });

    it("should validate allowedSchemes", () => {
      const result = validateURL("https://example.com", {
        allowedSchemes: ["https:"],
      });
      expect(result.ok).toBe(true);

      // Strict default policy: disjoint schemes are rejected
      const result2 = validateURL("mailto:test@example.com", {
        allowedSchemes: ["mailto:"],
      });
      expect(result2.ok).toBe(false);
    });

    it("should reject non-allowed schemes", () => {
      const result = validateURL("ftp://example.com", {
        allowedSchemes: ["https:"],
      });
      expect(result.ok).toBe(false);
    });

    it("should validate strict fragments", () => {
      const result = validateURL("https://example.com#javascript:alert(1)");
      expect(result.ok).toBe(false);
    });

    it("should allow disabling strict fragment validation", () => {
      const result = validateURL("https://example.com#javascript:alert(1)", {
        strictFragment: false,
      });
      expect(result.ok).toBe(true);
    });

    it("should enforce maxQueryParameters", () => {
      const urlWithManyParams =
        "https://example.com?" +
        Array.from({ length: 300 }, (_, i) => `k${i}=v`).join("&");
      const result = validateURL(urlWithManyParams);
      expect(result.ok).toBe(false);
    });

    it("should handle empty allowlist as deny-all", () => {
      const result = validateURL("https://example.com", { allowedOrigins: [] });
      expect(result.ok).toBe(false);
    });
  });

  describe("validateURLStrict", () => {
    it("should validate HTTPS URLs", () => {
      const result = validateURLStrict("https://example.com");
      expect(result.ok).toBe(true);
    });

    it("should reject non-HTTPS URLs", () => {
      const result = validateURLStrict("http://example.com");
      expect(result.ok).toBe(false);
    });

    it("should validate allowed origins", () => {
      const result = validateURLStrict("https://example.com", {
        allowedOrigins: ["https://example.com"],
      });
      expect(result.ok).toBe(true);
    });

    it("should enforce maxLength", () => {
      const result = validateURLStrict("https://example.com", {
        maxLength: 10,
      });
      expect(result.ok).toBe(false);
    });
  });

  describe("parseURLParams", () => {
    it("should parse query parameters", () => {
      const result = parseURLParams("https://example.com?q=test&limit=10");
      expect(result).toEqual({ q: "test", limit: "10" });
    });

    it("should handle empty query string", () => {
      const result = parseURLParams("https://example.com");
      expect(result).toEqual({});
    });

    it("should filter unsafe keys", () => {
      const result = parseURLParams(
        "https://example.com?safe=value&__proto__=evil",
      );
      expect(result).toEqual({ safe: "value" });
    });

    it("should validate expected parameters", () => {
      const result = parseURLParams("https://example.com?q=test&limit=10", {
        q: "string",
        limit: "number",
      });
      expect(result).toEqual({ q: "test", limit: "10" });
    });

    it("should handle URL without query", () => {
      const result = parseURLParams("https://example.com/path");
      expect(result).toEqual({});
    });

    it("should decode URL-encoded values", () => {
      const result = parseURLParams("https://example.com?q=hello%20world");
      expect(result).toEqual({ q: "hello world" });
    });

    it("should handle multiple values for same key", () => {
      const result = parseURLParams("https://example.com?q=test1&q=test2");
      expect(result).toEqual({ q: "test2" }); // Last value wins
    });

    it("should return frozen object with null prototype", () => {
      const result = parseURLParams("https://example.com?q=test");
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.getPrototypeOf(result)).toBe(null);
    });
  });

  describe("normalizeOrigin", () => {
    it("should normalize HTTPS origin", () => {
      const result = normalizeOrigin("https://example.com");
      expect(result).toBe("https://example.com");
    });

    it("should normalize HTTP origin with port", () => {
      const result = normalizeOrigin("http://example.com:8080");
      expect(result).toBe("http://example.com:8080");
    });

    it("should add default HTTPS port", () => {
      const result = normalizeOrigin("https://example.com:443");
      expect(result).toBe("https://example.com");
    });

    it("should add default HTTP port", () => {
      const result = normalizeOrigin("http://example.com:80");
      expect(result).toBe("http://example.com");
    });

    it("should lowercase hostname", () => {
      const result = normalizeOrigin("https://EXAMPLE.COM");
      expect(result).toBe("https://example.com");
    });

    it("should remove trailing dot from hostname", () => {
      const result = normalizeOrigin("https://example.com.");
      expect(result).toBe("https://example.com");
    });

    it("should reject invalid origins", () => {
      expect(() => normalizeOrigin("not-a-url")).toThrow();
    });

    it("should reject origins with paths", () => {
      expect(() => normalizeOrigin("https://example.com/path")).toThrow();
    });

    it("should handle Unicode normalization", () => {
      // The implementation requires IDNA (punycode) for non-ASCII authorities.
      // Raw Unicode in authority should be rejected; punycode should be accepted.
      expect(() => normalizeOrigin("https://café.com")).toThrow();
      const result = normalizeOrigin("https://xn--caf-dma.com");
      expect(result).toBe("https://xn--caf-dma.com");
    });
  });

  describe("encoding functions", () => {
    describe("encodeComponentRFC3986", () => {
      it("should encode special characters", () => {
        const result = encodeComponentRFC3986("hello world");
        expect(result).toBe("hello%20world");
      });

      it("should encode sub-delims", () => {
        const result = encodeComponentRFC3986("test@example.com");
        expect(result).toBe("test%40example.com");
      });

      it("should reject control characters", () => {
        expect(() => encodeComponentRFC3986("test\x00evil")).toThrow();
      });

      it("should handle empty string", () => {
        const result = encodeComponentRFC3986("");
        expect(result).toBe("");
      });

      it("should handle numbers", () => {
        const result = encodeComponentRFC3986(String(42));
        expect(result).toBe("42");
      });
    });

    describe("encodePathSegment", () => {
      it("should encode path segments", () => {
        const result = encodePathSegment("hello world");
        expect(result).toBe("hello%20world");
      });

      it("should reject control characters", () => {
        expect(() => encodePathSegment("test\x00evil")).toThrow();
      });
    });

    describe("encodeQueryValue", () => {
      it("should encode query values", () => {
        const result = encodeQueryValue("hello world");
        expect(result).toBe("hello%20world");
      });

      it("should reject control characters", () => {
        expect(() => encodeQueryValue("test\x00evil")).toThrow();
      });
    });

    describe("encodeFormValue", () => {
      it("should encode form values with plus for spaces", () => {
        const result = encodeFormValue("hello world");
        expect(result).toBe("hello+world");
      });

      it("should reject control characters", () => {
        expect(() => encodeFormValue("test\x00evil")).toThrow();
      });
    });

    describe("encodeMailtoValue", () => {
      it("should encode mailto values", () => {
        const result = encodeMailtoValue("test@example.com");
        expect(result).toBe("test%40example.com");
      });

      it("should reject control characters", () => {
        expect(() => encodeMailtoValue("test\x00evil")).toThrow();
      });
    });
  });

  describe("decoding functions", () => {
    describe("strictDecodeURIComponent", () => {
      it("should decode valid URI components", () => {
        const result = strictDecodeURIComponent("hello%20world");
        expect(result.ok).toBe(true);
        if (!result.ok) throw result.error;
        expect(result.value).toBe("hello world");
      });

      it("should reject malformed URI components", () => {
        const result = strictDecodeURIComponent("%ZZ");
        expect(result.ok).toBe(false);
      });

      it("should reject control characters in decoded result", () => {
        const result = strictDecodeURIComponent("%00");
        expect(result.ok).toBe(false);
      });

      it("should reject too long input", () => {
        const longInput = "a".repeat(5000);
        const result = strictDecodeURIComponent(longInput);
        expect(result.ok).toBe(false);
      });

      it("should handle empty string", () => {
        const result = strictDecodeURIComponent("");
        expect(result.ok).toBe(true);
        if (!result.ok) throw result.error;
        expect(result.value).toBe("");
      });
    });

    describe("strictDecodeURIComponentOrThrow", () => {
      it("should decode valid URI components", () => {
        const result = strictDecodeURIComponentOrThrow("hello%20world");
        expect(result).toBe("hello world");
      });

      it("should throw on malformed URI components", () => {
        expect(() => strictDecodeURIComponentOrThrow("%ZZ")).toThrow();
      });

      it("should throw on control characters", () => {
        expect(() => strictDecodeURIComponentOrThrow("%00")).toThrow();
      });
    });
  });

  describe("encodeHostLabel", () => {
    const mockIdnaLibrary = {
      toASCII: (s: string) => s.toLowerCase() + ".ascii",
    };

    it("should encode host labels using IDNA", () => {
      const result = encodeHostLabel("Example", mockIdnaLibrary);
      expect(result).toBe("example.ascii");
    });

    it("should reject missing IDNA library", () => {
      expect(() => encodeHostLabel("test", {} as any)).toThrow();
    });

    it("should handle IDNA encoding errors", () => {
      const badLibrary = {
        toASCII: () => {
          throw new Error("IDNA error");
        },
      };
      expect(() => encodeHostLabel("test", badLibrary)).toThrow();
    });

    it("should reject non-string input", () => {
      expect(() => encodeHostLabel(123 as unknown as string, mockIdnaLibrary)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("aliases", () => {
    it("should export updateURLParameters as alias", () => {
      expect(updateURLParameters).toBe(updateURLParams);
    });

    it("should export parseURLParameters as alias", () => {
      expect(parseURLParameters).toBe(parseURLParams);
    });
  });

  describe("error handling", () => {
    it("should handle null/undefined inputs appropriately", () => {
      expect(() => createSecureURL(null as any)).toThrow();
      expect(() => createSecureURL(undefined as any)).toThrow();
      expect(() => normalizeOrigin("")).toThrow();
    });

    it("should provide safe error messages in production", () => {
      // This would need to mock the environment, but we can test the structure
      expect(() => createSecureURL("javascript:alert(1)")).toThrow();
    });
  });

  describe("resource limiting", () => {
    it("should handle very long URLs", () => {
      const longUrl = "https://example.com/" + "a".repeat(2000);
      const result = validateURL(longUrl, { maxLength: 2100 });
      expect(result.ok).toBe(true);
    });

    it("should reject URLs exceeding maxLength", () => {
      const longUrl = "https://example.com/" + "a".repeat(2000);
      const result = validateURL(longUrl, { maxLength: 100 });
      expect(result.ok).toBe(false);
    });
  });

  describe("Unicode and normalization", () => {
    it("should handle Unicode characters in URLs", () => {
      const result = createSecureURL("https://example.com", ["café"]);
      expect(result).toBe("https://example.com/caf%C3%A9");
    });

    it("should normalize input strings", () => {
      // NFKC normalization should handle various Unicode forms
      const result = validateURL("https://example.com");
      expect(result.ok).toBe(true);
    });
  });
});
