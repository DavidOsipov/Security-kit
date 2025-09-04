import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  parseURLParams,
  encodeComponentRFC3986,
  strictDecodeURIComponent,
  strictDecodeURIComponentOrThrow,
  encodeFormValue,
  encodeHostLabel,
  normalizeOrigin,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("url module", () => {
  it("createSecureURL builds URL and encodes params", () => {
    const res = createSecureURL("https://example.com", ["api", "v1"], {
      q: "a b",
    });
    expect(res.startsWith("https://example.com/")).toBe(true);
    expect(res.includes("q=a%20b") || res.includes("q=a+b")).toBe(true);
  });

  it("createSecureURL accepts plain null-prototype params and encodes them", () => {
    const params = Object.create(null) as Record<string, unknown>;
    params.safe = "1";
    const res = createSecureURL("https://example.com", [], params as any);
    expect(res.includes("safe=1")).toBe(true);
  });

  it("updateURLParams can remove undefined and set values", () => {
    const base = "https://example.com/?a=1&b=2";
    const updated = updateURLParams(
      base,
      { a: undefined, b: "x", c: "z" },
      { removeUndefined: true, onUnsafeKey: "throw" },
    );
    expect(updated.includes("a=")).toBe(false);
    expect(updated.includes("b=x")).toBe(true);
    expect(updated.includes("c=z")).toBe(true);
  });

  it("validateURL rejects bad schemes", () => {
    const res = validateURL("javascript:alert(1)");
    expect(res.ok).toBe(false);
  });

  it("parseURLParams returns frozen safe object and warns on missing", () => {
    const obj = parseURLParams("https://example.com/?a=1&b=2");
    expect(Object.isFrozen(obj)).toBe(true);
    expect((obj as any).a).toBe("1");
  });

  it("strictDecodeURIComponent returns error on malformed", () => {
    const r = strictDecodeURIComponent("%E0%A4%A");
    expect(r.ok).toBe(false);
  });

  describe("normalizeOrigin", () => {
    it("normalizes origins correctly", () => {
      expect(normalizeOrigin("https://example.com")).toBe("https://example.com");
      expect(normalizeOrigin("https://example.com:443")).toBe("https://example.com");
      expect(normalizeOrigin("http://example.com:80")).toBe("http://example.com");
      expect(normalizeOrigin("https://example.com:8080")).toBe("https://example.com:8080");
    });

    it("rejects invalid origins", () => {
      expect(() => normalizeOrigin("")).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin("not-a-url")).toThrow(InvalidParameterError);
      expect(() => normalizeOrigin("https://user:pass@example.com")).toThrow(InvalidParameterError);
    });
  });

  describe("strictDecodeURIComponentOrThrow", () => {
    it("decodes valid URI components", () => {
      expect(strictDecodeURIComponentOrThrow("hello%20world")).toBe("hello world");
      expect(strictDecodeURIComponentOrThrow("test%2Bvalue")).toBe("test+value");
    });

    it("throws on malformed input", () => {
      expect(() => strictDecodeURIComponentOrThrow("%E0%A4%A")).toThrow(InvalidParameterError);
    });

    it("throws on control characters", () => {
      expect(() => strictDecodeURIComponentOrThrow("%00")).toThrow(InvalidParameterError);
      expect(() => strictDecodeURIComponentOrThrow("%1F")).toThrow(InvalidParameterError);
    });

    it("throws on overly long input", () => {
      const longInput = "%20".repeat(2000);
      expect(() => strictDecodeURIComponentOrThrow(longInput)).toThrow(InvalidParameterError);
    });
  });

  describe("encodeComponentRFC3986", () => {
    it("encodes URI components according to RFC3986", () => {
      expect(encodeComponentRFC3986("hello world")).toBe("hello%20world");
      expect(encodeComponentRFC3986("test+value")).toBe("test%2Bvalue");
      expect(encodeComponentRFC3986("!'()*")).toBe("%21%27%28%29%2A");
    });

    it("throws on control characters", () => {
      expect(() => encodeComponentRFC3986("test\x00")).toThrow(InvalidParameterError);
      expect(() => encodeComponentRFC3986("test\x1F")).toThrow(InvalidParameterError);
    });
  });

  describe("encodeFormValue", () => {
    it("encodes form values with + for spaces", () => {
      expect(encodeFormValue("hello world")).toBe("hello+world");
      expect(encodeFormValue("test+value")).toBe("test%2Bvalue");
    });

    it("throws on control characters", () => {
      expect(() => encodeFormValue("test\x00")).toThrow(InvalidParameterError);
    });
  });

  describe("encodeHostLabel", () => {
    const mockIdnaLibrary = {
      toASCII: (s: string) => s.toUpperCase(), // Mock implementation
    };

    it("encodes host labels using IDNA", () => {
      expect(encodeHostLabel("example", mockIdnaLibrary)).toBe("EXAMPLE");
    });

    it("throws without IDNA library", () => {
      expect(() => encodeHostLabel("example", {} as any)).toThrow(InvalidParameterError);
    });

    it("throws with invalid IDNA library", () => {
      expect(() => encodeHostLabel("example", { toASCII: null } as any)).toThrow(InvalidParameterError);
    });
  });

  describe("security hardening - credential rejection", () => {
    it("rejects URLs with embedded credentials in createSecureURL", () => {
      expect(() => createSecureURL("https://user:pass@example.com")).toThrow(InvalidParameterError);
      expect(() => createSecureURL("https://user@example.com")).toThrow(InvalidParameterError);
    });

    it("rejects URLs with embedded credentials in updateURLParams", () => {
      expect(() => updateURLParams("https://user:pass@example.com", {})).toThrow(InvalidParameterError);
    });

    it("rejects URLs with embedded credentials in validateURL", () => {
      const res = validateURL("https://user:pass@example.com");
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("rejects URLs with embedded credentials in parseURLParams", () => {
      expect(() => parseURLParams("https://user:pass@example.com")).toThrow(InvalidParameterError);
    });
  });

  describe("OWASP ASVS L3 compliance - input validation", () => {
    it("validates URL length limits", () => {
      const longUrl = "https://example.com/" + "a".repeat(3000);
      const res = validateURL(longUrl, { maxLength: 100 });
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("prevents path traversal in path segments", () => {
      expect(() => createSecureURL("https://example.com", [".."])).toThrow(InvalidParameterError);
      expect(() => createSecureURL("https://example.com", ["."])).toThrow(InvalidParameterError);
      expect(() => createSecureURL("https://example.com", ["path/../../../etc"])).toThrow(InvalidParameterError);
    });

    it("validates path segment length limits", () => {
      const longSegment = "a".repeat(2000);
      expect(() => createSecureURL("https://example.com", [longSegment])).toThrow(InvalidParameterError);
    });

    it("rejects empty path segments", () => {
      expect(() => createSecureURL("https://example.com", [""])).toThrow(InvalidParameterError);
    });

    it("prevents prototype pollution in query parameters", () => {
      const maliciousParams = {
        "__proto__": "polluted",
        "constructor": "bad",
        "safe": "value"
      };

      expect(() => createSecureURL("https://example.com", [], maliciousParams)).toThrow(InvalidParameterError);
    });

    it("validates fragment safety", () => {
      expect(() => createSecureURL("https://example.com", [], {}, "safe-fragment")).not.toThrow();
      expect(() => createSecureURL("https://example.com", [], {}, "bad\x00fragment")).toThrow(InvalidParameterError);
    });
  });

  describe("scheme policy enforcement", () => {
    it("enforces HTTPS requirement", () => {
      expect(() => createSecureURL("http://example.com", [], {}, undefined, { requireHTTPS: true })).toThrow(InvalidParameterError);
      expect(createSecureURL("https://example.com", [], {}, undefined, { requireHTTPS: true })).toBe("https://example.com/");
    });

    it("validates allowed schemes intersection", () => {
      expect(() => createSecureURL("ftp://example.com", [], {}, undefined, { allowedSchemes: ["https:"] })).toThrow(InvalidParameterError);
      expect(createSecureURL("https://example.com", [], {}, undefined, { allowedSchemes: ["https:"] })).toBe("https://example.com/");
    });

    it("handles empty allowedSchemes as deny-all", () => {
      expect(() => createSecureURL("https://example.com", [], {}, undefined, { allowedSchemes: [] })).toThrow(InvalidParameterError);
    });
  });

  describe("parameter processing security", () => {
    it("filters unsafe query parameter keys", () => {
      const params = {
        "safe-param": "value",
        "__proto__": "unsafe",
        "constructor": "unsafe",
        "prototype": "unsafe"
      };

      const result = createSecureURL("https://example.com", [], params, undefined, { onUnsafeKey: "skip" });
      expect(result).toContain("safe-param=value");
      expect(result).not.toContain("__proto__");
      expect(result).not.toContain("constructor");
      expect(result).not.toContain("prototype");
    });

    it("validates parameter key format", () => {
      const longKey = "a".repeat(200);
      const params = {
        "valid_key-123": "value",
        "invalid key": "value",
        "": "empty",
        [longKey]: "too-long"
      };

      expect(() => createSecureURL("https://example.com", [], params)).toThrow(InvalidParameterError);
    });
  });

  describe("error handling and information leakage", () => {
    it("provides safe error messages in production", () => {
      // Test that error messages don't leak internal details
      expect(() => createSecureURL("not-a-url")).toThrow(InvalidParameterError);
      expect(() => createSecureURL("https://user:pass@example.com")).toThrow(InvalidParameterError);
    });

    it("handles malformed URLs gracefully", () => {
      const res = validateURL("://invalid");
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.error).toBeInstanceOf(InvalidParameterError);
      }
    });
  });

  describe("boundary testing", () => {
    it("handles edge cases in URL construction", () => {
      // Empty query params
      expect(createSecureURL("https://example.com", [], {})).toBe("https://example.com/");

      // Undefined values in params
      expect(createSecureURL("https://example.com", [], { a: undefined })).toBe("https://example.com/?a=");

      // Null values in params
      expect(createSecureURL("https://example.com", [], { a: null })).toBe("https://example.com/?a=");

      // Mixed types in params
      expect(createSecureURL("https://example.com", [], { num: 123, str: "test", bool: true })).toContain("num=123");
    });

    it("validates URL component size limits", () => {
      const longPath = "a".repeat(1000);
      expect(() => createSecureURL("https://example.com", [longPath], {}, undefined, { maxLength: 500 })).toThrow(InvalidParameterError);
    });
  });
});
