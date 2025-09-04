import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  parseURLParams,
  normalizeOrigin,
  strictDecodeURIComponent,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("url.ts uncovered branches - comprehensive coverage", () => {
  describe("requireHTTPS enforcement", () => {
    it("createSecureURL throws when requireHTTPS=true but scheme is not https", () => {
      expect(() =>
        createSecureURL("http://example.com", [], {}, undefined, {
          requireHTTPS: true,
        })
      ).toThrow(InvalidParameterError);
    });

    it("updateURLParams throws when requireHTTPS=true but scheme is not https", () => {
      expect(() =>
        updateURLParams("http://example.com", {}, { requireHTTPS: true })
      ).toThrow(InvalidParameterError);
    });

    it("createSecureURL allows https when requireHTTPS=true", () => {
      const result = createSecureURL("https://example.com", [], {}, undefined, {
        requireHTTPS: true,
      });
      expect(result).toBe("https://example.com/");
    });

    it("updateURLParams allows https when requireHTTPS=true", () => {
      const result = updateURLParams("https://example.com", {}, {
        requireHTTPS: true,
      });
      expect(result).toBe("https://example.com/");
    });
  });

  describe("allowedSchemes empty intersection error", () => {
    it("createSecureURL throws when allowedSchemes has no intersection with policy", () => {
      expect(() =>
        createSecureURL("ftp://example.com", [], {}, undefined, {
          allowedSchemes: ["https:"],
        })
      ).toThrow(InvalidParameterError);
    });

    it("validateURL rejects when allowedSchemes has no intersection with policy", () => {
      const result = validateURL("ftp://example.com", {
        allowedSchemes: ["https:"],
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("createSecureURL allows when allowedSchemes intersects with policy", () => {
      const result = createSecureURL("https://example.com", [], {}, undefined, {
        allowedSchemes: ["https:", "http:"],
      });
      expect(result).toBe("https://example.com/");
    });
  });

  describe("credential rejection across all APIs", () => {
    it("normalizeOrigin rejects URLs with username", () => {
      expect(() => normalizeOrigin("https://user@example.com")).toThrow(
        InvalidParameterError
      );
    });

    it("normalizeOrigin rejects URLs with password", () => {
      expect(() => normalizeOrigin("https://user:pass@example.com")).toThrow(
        InvalidParameterError
      );
    });

    it("validateURL rejects URLs with username", () => {
      const result = validateURL("https://user@example.com");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("validateURL rejects URLs with password", () => {
      const result = validateURL("https://user:pass@example.com");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });
  });

  describe("fragment control character rejection", () => {
    it("createSecureURL rejects fragment with null character", () => {
      expect(() =>
        createSecureURL("https://example.com", [], {}, "fragment\x00")
      ).toThrow(InvalidParameterError);
    });

    it("createSecureURL rejects fragment with control character", () => {
      expect(() =>
        createSecureURL("https://example.com", [], {}, "fragment\x1F")
      ).toThrow(InvalidParameterError);
    });

    it("createSecureURL allows safe fragment", () => {
      const result = createSecureURL("https://example.com", [], {}, "safe-fragment");
      expect(result).toBe("https://example.com/#safe-fragment");
    });
  });

  describe("Map input handling", () => {
    it("createSecureURL accepts Map for queryParameters", () => {
      const params = new Map([
        ["key1", "value1"],
        ["key2", "value2"],
      ]);
      const result = createSecureURL("https://example.com", [], params);
      expect(result).toContain("key1=value1");
      expect(result).toContain("key2=value2");
    });

    it("updateURLParams accepts Map for updates", () => {
      const updates = new Map([
        ["key1", "newvalue1"],
        ["key2", undefined],
      ]);
      const result = updateURLParams("https://example.com?key1=old&key2=old", updates, {
        removeUndefined: true,
      });
      expect(result).toContain("key1=newvalue1");
      expect(result).not.toContain("key2=");
    });

    it("createSecureURL rejects Map with dangerous keys", () => {
      const params = new Map([
        ["safe", "value"],
        ["__proto__", "dangerous"],
      ]);
      expect(() => createSecureURL("https://example.com", [], params)).toThrow(
        InvalidParameterError
      );
    });
  });

  describe("removeUndefined behavior in updateURLParams", () => {
    it("removes undefined values when removeUndefined=true", () => {
      const result = updateURLParams("https://example.com?a=1&b=2&c=3", {
        a: undefined,
        b: "new",
        c: undefined,
      }, { removeUndefined: true });
      expect(result).not.toContain("a=");
      expect(result).toContain("b=new");
      expect(result).not.toContain("c=");
    });

    it("keeps undefined values as empty when removeUndefined=false", () => {
      const result = updateURLParams("https://example.com?a=1&b=2&c=3", {
        a: undefined,
        b: "new",
        c: undefined,
      }, { removeUndefined: false });
      expect(result).toContain("a=");
      expect(result).toContain("b=new");
      expect(result).toContain("c=");
    });

    it("defaults to removeUndefined=true", () => {
      const result = updateURLParams("https://example.com?a=1", {
        a: undefined,
      });
      expect(result).not.toContain("a=");
    });
  });

  describe("validateURL edge cases", () => {
    it("validateURL rejects non-string input", () => {
      const result = validateURL(123 as any);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("validateURL rejects URLs exceeding maxLength", () => {
      const longUrl = "https://example.com/" + "a".repeat(3000);
      const result = validateURL(longUrl, { maxLength: 100 });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("validateURL enforces HTTPS when required", () => {
      const result = validateURL("http://example.com", { requireHTTPS: true });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("validateURL rejects disallowed schemes", () => {
      const result = validateURL("ftp://example.com", {
        allowedSchemes: ["https:"],
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("validateURL rejects non-allowlisted origins", () => {
      const result = validateURL("https://evil.com", {
        allowedOrigins: ["https://trusted.com"],
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });
  });

  describe("parseURLParams edge cases", () => {
    it("parseURLParams rejects non-string input", () => {
      expect(() => parseURLParams(123 as any)).toThrow(InvalidParameterError);
    });

    it("parseURLParams filters unsafe keys", () => {
      const result = parseURLParams("https://example.com?safe=value&__proto__=dangerous");
      expect(result.safe).toBe("value");
      expect(result.__proto__).toBeUndefined();
    });

    it("parseURLParams validates expected parameters", () => {
      const result = parseURLParams("https://example.com?a=1&b=notanumber", {
        a: "string",
        b: "number",
        c: "string",
      });
      expect(result.a).toBe("1");
      expect(result.b).toBe("notanumber");
      expect(result.c).toBeUndefined();
    });

    it("parseURLParams handles empty query string", () => {
      const result = parseURLParams("https://example.com");
      expect(Object.keys(result)).toHaveLength(0);
    });
  });

  describe("strictDecodeURIComponent edge cases", () => {
    it("strictDecodeURIComponent rejects overly long input", () => {
      const longInput = "%20".repeat(2000);
      const result = strictDecodeURIComponent(longInput);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });

    it("strictDecodeURIComponent rejects control characters in decoded output", () => {
      const result = strictDecodeURIComponent("%00");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    });
  });

  describe("path segment validation", () => {
    it("createSecureURL rejects path segments with separators", () => {
      expect(() =>
        createSecureURL("https://example.com", ["path/../../../etc"])
      ).toThrow(InvalidParameterError);
    });

    it("createSecureURL rejects path segments with backslashes", () => {
      expect(() =>
        createSecureURL("https://example.com", ["path\\windows"])
      ).toThrow(InvalidParameterError);
    });

    it("createSecureURL rejects single dot path segment", () => {
      expect(() => createSecureURL("https://example.com", ["."])).toThrow(
        InvalidParameterError
      );
    });

    it("createSecureURL rejects double dot path segment", () => {
      expect(() => createSecureURL("https://example.com", [".."])).toThrow(
        InvalidParameterError
      );
    });
  });

  describe("URL length validation", () => {
    it("createSecureURL enforces maxLength", () => {
      expect(() =>
        createSecureURL("https://example.com", ["a".repeat(1000)], {}, undefined, {
          maxLength: 100,
        })
      ).toThrow(InvalidParameterError);
    });

    it("updateURLParams enforces maxLength", () => {
      expect(() =>
        updateURLParams("https://example.com", { long: "a".repeat(1000) }, {
          maxLength: 100,
        })
      ).toThrow(InvalidParameterError);
    });
  });
});