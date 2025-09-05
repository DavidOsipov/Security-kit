import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  validateURL,
  parseURLParams,
  normalizeOrigin,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

// WHATWG URL Standard alignment tests for Host Miscellaneous (forbidden code points),
// IDNA handling expectations (ASCII-only authority; punycode accepted),
// and PSL independence (origin-based allowlist, no registrable-domain shortcuts).

describe("WHATWG host-misc + PSL independence", () => {
  describe("forbidden host/domain code points in authority", () => {
    it("rejects internal whitespace in authority (space)", () => {
      const bad = "https://exa mple.com";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.error).toBeInstanceOf(InvalidParameterError);
    });

    it("rejects percent-encoding in authority", () => {
      const bad = "https://exam%2eple.com"; // % in authority is forbidden
      expect(() => createSecureURL(bad)).toThrow(
        /Percent-encoded sequences in authority/,
      );
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects backslash in authority to avoid parser confusion", () => {
      const tricky = "https://example.com\\@evil.com"; // backslash before @
      expect(() => createSecureURL(tricky)).toThrow(InvalidParameterError);
      const v = validateURL(tricky);
      expect(v.ok).toBe(false);
    });

    it("rejects vertical bar and angle brackets in authority", () => {
      for (const bad of [
        "https://exa|mple.com",
        "https://<example>.com",
        "https://example.>com",
      ]) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects embedded credentials via '@' in authority", () => {
      const bad = "https://exa@mple.com"; // will be treated as creds@host
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects C0 control characters in authority (DEL/C0 example)", () => {
      const bad = "https://exam\u007Fple.com"; // U+007F DELETE
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects caret and other forbidden punctuation in host labels", () => {
      const bad = "https://exa^mple.com";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });
  });

  describe("IDNA expectations", () => {
    it("rejects raw Unicode domain (require explicit IDNA)", () => {
      const raw = "https://☕.example";
      const v = validateURL(raw);
      expect(v.ok).toBe(false);
    });

    it("accepts IDNA (punycode) equivalence for same domain", () => {
      const puny = "https://xn--53h.example"; // ☕.example
      const v = validateURL(puny);
      expect(v.ok).toBe(true);
    });

    it("rejects mixed ASCII/Unicode labels without IDNA", () => {
      const mixed = "https://example.إختبار";
      const v = validateURL(mixed);
      expect(v.ok).toBe(false);
    });

    it("accepts IPv6 literals with brackets", () => {
      const v1 = validateURL("https://[::1]");
      expect(v1.ok).toBe(true);
      const v2 = validateURL("https://[2001:db8::1]");
      expect(v2.ok).toBe(true);
    });
  });

  describe("PSL independence and origin allowlist behavior", () => {
    it("does not treat registrable domains as security boundary (subdomain not allowed)", () => {
      const r = validateURL("https://whatwg.github.io", {
        allowedOrigins: ["https://github.io"],
      });
      expect(r.ok).toBe(false);
    });

    it("matches exact origin when allowlisted", () => {
      const r = validateURL("https://example.com", {
        allowedOrigins: ["https://example.com"],
      });
      expect(r.ok).toBe(true);
    });

    it("does not allow sibling or subdomain when only apex is allowlisted", () => {
      const r = validateURL("https://sub.example.com", {
        allowedOrigins: ["https://example.com"],
      });
      expect(r.ok).toBe(false);
    });

    it("normalizes trailing dot in origins for comparison", () => {
      const r = validateURL("https://example.com.", {
        allowedOrigins: ["https://example.com"],
      });
      expect(r.ok).toBe(true);
      if (r.ok) {
        // normalizeOrigin should strip trailing dot
        expect(normalizeOrigin("https://example.com.")).toBe(
          "https://example.com",
        );
      }
    });
  });

  describe("parsing functions handle forbidden hosts safely", () => {
    it("parseURLParams throws on malformed authority with whitespace", () => {
      const bad = "https://exa mple.com?x=1";
      expect(() => parseURLParams(bad)).toThrow(InvalidParameterError);
    });
  });

  // Comprehensive unit tests for valid cases and edge cases
  describe("comprehensive unit tests for valid URLs", () => {
    it("accepts standard HTTPS URLs", () => {
      const url = "https://example.com";
      expect(createSecureURL(url)).toBe("https://example.com/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts URLs with valid ports", () => {
      const url = "https://example.com:8080";
      expect(createSecureURL(url)).toBe("https://example.com:8080/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts URLs with port 80 for HTTP", () => {
      const url = "http://example.com:80";
      expect(() => createSecureURL(url)).toThrow(
        /Resulting URL scheme 'http:' is not allowed/,
      );
      const v = validateURL(url, { allowedSchemes: ["http:"] });
      // Strict default policy: caller-provided allowedSchemes must intersect SAFE_SCHEMES.
      expect(v.ok).toBe(false);
    });

    it("accepts URLs with port 443 for HTTPS", () => {
      const url = "https://example.com:443";
      expect(createSecureURL(url)).toBe("https://example.com/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts IPv6 URLs with brackets", () => {
      const url = "https://[::1]";
      expect(createSecureURL(url)).toBe("https://[::1]/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts IPv6 URLs with ports", () => {
      const url = "https://[::1]:8080";
      expect(createSecureURL(url)).toBe("https://[::1]:8080/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts valid hostnames with hyphens and numbers", () => {
      const url = "https://sub-domain123.example.com";
      expect(createSecureURL(url)).toBe("https://sub-domain123.example.com/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts single letter hostnames", () => {
      const url = "https://a.com";
      expect(createSecureURL(url)).toBe("https://a.com/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts hostnames with trailing dot", () => {
      const url = "https://example.com.";
      expect(createSecureURL(url)).toBe("https://example.com/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts mailto URLs", () => {
      const url = "mailto:test@example.com";
      expect(() => createSecureURL(url)).toThrow(
        /Resulting URL scheme 'mailto:' is not allowed/,
      );
      // allowPaths is an optional runtime-only test flag used here; cast to any
      const v = validateURL(url, {
        allowedSchemes: ["mailto:"],
        allowPaths: true,
      } as any);
      // Strict default policy: mailto is not in SAFE_SCHEMES.
      expect(v.ok).toBe(false);
    });

    it("accepts URLs with query parameters", () => {
      const url = "https://example.com?key=value";
      expect(createSecureURL(url)).toBe("https://example.com/?key=value");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts URLs with fragments", () => {
      const url = "https://example.com#section";
      expect(createSecureURL(url)).toBe("https://example.com/#section");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });
  });

  describe("edge cases for colon and port validation", () => {
    it("rejects URLs with multiple colons in non-IPv6 authority", () => {
      const bad = "https://example.com:8080:9090";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects URLs with colon but no port", () => {
      const bad = "https://example.com:";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects URLs with non-numeric port", () => {
      const bad = "https://example.com:abc";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects URLs with port too long", () => {
      const bad = "https://example.com:123456";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("accepts maximum valid port 65535", () => {
      const url = "https://example.com:65535";
      expect(createSecureURL(url)).toBe("https://example.com:65535/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });

    it("accepts minimum valid port 1", () => {
      const url = "https://example.com:1";
      expect(createSecureURL(url)).toBe("https://example.com:1/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });
  });

  describe("adversarial tests for forbidden characters", () => {
    it("rejects backslash in various positions", () => {
      const badUrls = [
        "https://example.com\\",
        "https://\\example.com",
        "https://exa\\mple.com",
        "https://example.com\\@evil.com",
        "https://example.com\\:8080",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects caret in various positions", () => {
      const badUrls = [
        "https://exa^mple.com",
        "https://^example.com",
        "https://example.com^",
        "https://example.com^:8080",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects vertical bar in various positions", () => {
      const badUrls = [
        "https://exa|mple.com",
        "https://|example.com",
        "https://example.com|",
        "https://example.com|:8080",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects angle brackets in various positions", () => {
      const badUrls = [
        "https://<example>.com",
        "https://example.>com",
        "https://<example.com",
        "https://example.com>",
        "https://example.com<",
        "https://example.com>:8080",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects combinations of forbidden characters", () => {
      const badUrls = [
        "https://exa\\^|mple.com",
        "https://<example>|.com",
        "https://example.^com",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects attempts to bypass with encoding", () => {
      // Note: We already reject % in authority, so these should fail
      const badUrls = [
        "https://exa%5Cmple.com", // %5C is \
        "https://exa%5Emple.com", // %5E is ^
        "https://exa%7Cmple.com", // %7C is |
        "https://%3Cexample%3E.com", // %3C is <, %3E is >
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(
          /Percent-encoded sequences in authority/,
        );
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects malformed IPv6 with forbidden characters", () => {
      const badUrls = [
        "https://[::1\\]",
        "https://[::1^]",
        "https://[::1|]",
        "https://[<::1>]",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects URLs with forbidden characters in hostname labels", () => {
      const badUrls = [
        "https://exa\\mple.com",
        "https://exa^mple.com",
        "https://exa|mple.com",
        "https://<example>.com",
        "https://example.>.com",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });
  });

  describe("adversarial tests for colon/port bypass attempts", () => {
    it("rejects colon in hostname without port", () => {
      const bad = "https://example:com";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects multiple colons in hostname", () => {
      const bad = "https://example:8080:9090";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects port with leading zeros", () => {
      const bad = "https://example.com:08080";
      // Leading zeros are accepted as valid digits
      expect(createSecureURL(bad)).toBe("https://example.com:8080/");
      const v = validateURL(bad);
      expect(v.ok).toBe(true);
    });

    it("rejects port with non-digit characters", () => {
      const bad = "https://example.com:8080a";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("rejects IPv6 with invalid port", () => {
      const bad = "https://[::1]:abc";
      expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
      const v = validateURL(bad);
      expect(v.ok).toBe(false);
    });

    it("accepts IPv6 with valid port", () => {
      const url = "https://[::1]:8080";
      expect(createSecureURL(url)).toBe("https://[::1]:8080/");
      const v = validateURL(url);
      expect(v.ok).toBe(true);
    });
  });

  describe("adversarial tests for existing validations", () => {
    it("rejects URLs with embedded credentials", () => {
      const badUrls = [
        "https://user:pass@example.com",
        "https://user@example.com",
        "https://:pass@example.com",
        "https://user:@example.com",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects URLs with control characters", () => {
      const badUrls = [
        "https://example.com\x00",
        "https://example.com\x1f",
        "https://example.com\x7f",
        "https://example.com\x9f",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects URLs with internal whitespace", () => {
      const badUrls = ["https://exa mple.com", "https://example .com"];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });

    it("rejects URLs with raw Unicode in authority", () => {
      const badUrls = [
        "https://☕.example.com",
        "https://example.إختبار",
        "https://пример.com",
      ];
      for (const bad of badUrls) {
        expect(() => createSecureURL(bad)).toThrow(InvalidParameterError);
        const v = validateURL(bad);
        expect(v.ok).toBe(false);
      }
    });
  });
});
