import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  Sanitizer,
  STRICT_HTML_POLICY_CONFIG,
  HARDENED_SVG_POLICY_CONFIG,
  SANITIZER_ESLINT_RECOMMENDATIONS,
  type SanitizerPolicies,
} from "../../src/sanitizer.js";
import {
  InvalidParameterError,
  InvalidConfigurationError,
} from "../../src/errors.js";

// Mock DOMPurify
const mockDOMPurify = {
  sanitize: vi.fn(),
};

// Mock window.trustedTypes
const mockCreatePolicy = vi.fn();
const mockTrustedTypes = {
  createPolicy: mockCreatePolicy,
};

describe("sanitizer", () => {
  let originalWindow: any;

  beforeEach(() => {
    originalWindow = global.window;
    global.window = {
      trustedTypes: mockTrustedTypes,
    } as any;
    vi.clearAllMocks();
  });

  afterEach(() => {
    global.window = originalWindow;
  });

  describe("pre-defined configurations", () => {
    it("STRICT_HTML_POLICY_CONFIG has correct settings", () => {
      expect(STRICT_HTML_POLICY_CONFIG.USE_PROFILES).toEqual({
        html: true,
        svg: false,
        mathml: false,
      });
      expect(STRICT_HTML_POLICY_CONFIG.RETURN_TRUSTED_TYPE).toBe(true);
      expect(STRICT_HTML_POLICY_CONFIG.FORBID_TAGS).toBeUndefined();
      expect(STRICT_HTML_POLICY_CONFIG.FORBID_ATTR).toBeUndefined();
    });

    it("HARDENED_SVG_POLICY_CONFIG has correct settings", () => {
      expect(HARDENED_SVG_POLICY_CONFIG.USE_PROFILES).toEqual({
        html: true,
        svg: true,
        mathml: false,
      });
      expect(HARDENED_SVG_POLICY_CONFIG.RETURN_TRUSTED_TYPE).toBe(true);
      expect(HARDENED_SVG_POLICY_CONFIG.FORBID_TAGS).toEqual([
        "script",
        "style",
        "iframe",
        "foreignObject",
        "form",
        "a",
      ]);
      expect(HARDENED_SVG_POLICY_CONFIG.FORBID_ATTR).toEqual([
        "onclick",
        "onerror",
        "onload",
        "onmouseover",
        "href",
      ]);
    });

    it("configurations are frozen", () => {
      expect(() => {
        (STRICT_HTML_POLICY_CONFIG as any).USE_PROFILES = { html: false };
      }).toThrow();
      expect(() => {
        (HARDENED_SVG_POLICY_CONFIG as any).FORBID_TAGS = [];
      }).toThrow();
    });
  });

  describe("SANITIZER_ESLINT_RECOMMENDATIONS", () => {
    it("contains expected recommendations", () => {
      expect(SANITIZER_ESLINT_RECOMMENDATIONS).toEqual([
        "security/no-unsafe-innerhtml",
        "no-restricted-syntax (disallow direct innerHTML assignment)",
        "prefer using Sanitizer.safeSetInnerHTML for DOM updates",
      ]);
    });

    it("is frozen", () => {
      expect(() => {
        (SANITIZER_ESLINT_RECOMMENDATIONS as any).push("new-rule");
      }).toThrow();
    });
  });

  describe("Sanitizer class", () => {
    let policies: SanitizerPolicies;
    let sanitizer: Sanitizer;

    beforeEach(() => {
      policies = {
        strict: STRICT_HTML_POLICY_CONFIG,
        svg: HARDENED_SVG_POLICY_CONFIG,
      };
      sanitizer = new Sanitizer(mockDOMPurify, policies);
    });

    describe("constructor", () => {
      it("accepts valid DOMPurify instance and policies", () => {
        expect(() => new Sanitizer(mockDOMPurify, policies)).not.toThrow();
      });

      it("throws InvalidParameterError for invalid DOMPurify instance", () => {
        expect(() => new Sanitizer(null as any, policies)).toThrow(
          InvalidParameterError,
        );
        expect(() => new Sanitizer({} as any, policies)).toThrow(
          InvalidParameterError,
        );
        expect(
          () => new Sanitizer({ sanitize: "not-a-function" } as any, policies),
        ).toThrow(InvalidParameterError);
      });

      it("accepts empty policies object", () => {
        expect(() => new Sanitizer(mockDOMPurify, {})).not.toThrow();
      });
    });

    describe("createPolicy", () => {
      beforeEach(() => {
        mockCreatePolicy.mockReturnValue({
          createHTML: vi.fn(),
        });
        mockDOMPurify.sanitize.mockReturnValue("<p>safe</p>" as any);
      });

      it("creates and caches a policy successfully", () => {
        const policy = sanitizer.createPolicy("strict");

        expect(mockCreatePolicy).toHaveBeenCalledWith("strict", {
          createHTML: expect.any(Function),
          createScript: expect.any(Function),
          createScriptURL: expect.any(Function),
        });
        expect(policy).toBeDefined();
      });

      it("returns cached policy on subsequent calls", () => {
        const policy1 = sanitizer.createPolicy("strict");
        const policy2 = sanitizer.createPolicy("strict");

        expect(policy1).toBe(policy2);
        expect(mockCreatePolicy).toHaveBeenCalledTimes(1);
      });

      it("throws InvalidConfigurationError for unknown policy", () => {
        expect(() => sanitizer.createPolicy("unknown")).toThrow(
          InvalidConfigurationError,
        );
      });

      it("throws InvalidConfigurationError when Trusted Types unavailable", () => {
        delete (global.window as any).trustedTypes;

        expect(() => sanitizer.createPolicy("strict")).toThrow(
          InvalidConfigurationError,
        );
      });

      it("calls DOMPurify.sanitize with correct config", () => {
        const createHTML = vi.fn();
        mockCreatePolicy.mockImplementation((name, rules) => {
          createHTML.mockImplementation(rules.createHTML);
          return { createHTML };
        });

        sanitizer.createPolicy("strict");

        createHTML("<script>alert(1)</script><p>safe</p>");

        expect(mockDOMPurify.sanitize).toHaveBeenCalledWith(
          "<script>alert(1)</script><p>safe</p>",
          {
            ...STRICT_HTML_POLICY_CONFIG,
            RETURN_TRUSTED_TYPE: true,
          },
        );
      });

      it("throws InvalidParameterError for script creation attempts", () => {
        mockCreatePolicy.mockImplementation((name, rules) => ({
          createScript: rules.createScript,
          createScriptURL: rules.createScriptURL,
        }));

        sanitizer.createPolicy("strict");

        // The createScript function should throw when called
        const policy = mockCreatePolicy.mock.results[0].value;
        expect(() => policy.createScript()).toThrow(InvalidParameterError);
      });

      it("throws InvalidParameterError for script URL creation attempts", () => {
        mockCreatePolicy.mockImplementation((name, rules) => ({
          createScript: rules.createScript,
          createScriptURL: rules.createScriptURL,
        }));

        sanitizer.createPolicy("strict");

        // The createScriptURL function should throw when called
        const policy = mockCreatePolicy.mock.results[0].value;
        expect(() => policy.createScriptURL()).toThrow(InvalidParameterError);
      });
    });

    describe("sanitizeForNonTTBrowsers", () => {
      beforeEach(() => {
        mockDOMPurify.sanitize.mockReturnValue("<p>sanitized</p>");
      });

      it("sanitizes HTML with correct config", () => {
        const result = sanitizer.sanitizeForNonTTBrowsers(
          "<script>evil</script><p>good</p>",
          "strict",
        );

        expect(mockDOMPurify.sanitize).toHaveBeenCalledWith(
          "<script>evil</script><p>good</p>",
          {
            ...STRICT_HTML_POLICY_CONFIG,
            RETURN_TRUSTED_TYPE: false,
          },
        );
        expect(result).toBe("<p>sanitized</p>");
      });

      it("throws InvalidConfigurationError for unknown policy", () => {
        expect(() =>
          sanitizer.sanitizeForNonTTBrowsers("html", "unknown"),
        ).toThrow(InvalidConfigurationError);
      });
    });

    describe("createPolicyIfAvailable", () => {
      beforeEach(() => {
        mockCreatePolicy.mockReturnValue({
          createHTML: vi.fn(),
        });
        mockDOMPurify.sanitize.mockReturnValue("<p>safe</p>" as any);
      });

      it("returns policy when Trusted Types available", () => {
        const policy = sanitizer.createPolicyIfAvailable("strict");
        expect(policy).toBeDefined();
      });

      it("returns undefined when window is undefined", () => {
        const originalWindow = global.window;
        delete (global as any).window;
        const policy = sanitizer.createPolicyIfAvailable("strict");
        expect(policy).toBeUndefined();
        global.window = originalWindow;
      });

      it("returns undefined when trustedTypes unavailable", () => {
        delete (global.window as any).trustedTypes;
        const policy = sanitizer.createPolicyIfAvailable("strict");
        expect(policy).toBeUndefined();
      });

      it("returns undefined when createPolicy unavailable", () => {
        (global.window as any).trustedTypes = {};
        const policy = sanitizer.createPolicyIfAvailable("strict");
        expect(policy).toBeUndefined();
      });

      it("throws InvalidConfigurationError for unknown policy", () => {
        expect(() => sanitizer.createPolicyIfAvailable("unknown")).toThrow(
          InvalidConfigurationError,
        );
      });

      it("returns undefined when policy creation fails", () => {
        mockCreatePolicy.mockImplementation(() => {
          throw new Error("Policy creation failed");
        });

        const policy = sanitizer.createPolicyIfAvailable("strict");
        expect(policy).toBeUndefined();
      });
    });

    describe("getSanitizedString", () => {
      beforeEach(() => {
        mockDOMPurify.sanitize.mockReturnValue("<p>sanitized</p>");
      });

      it("returns sanitized string", () => {
        const result = sanitizer.getSanitizedString(
          "<script>evil</script><p>good</p>",
          "strict",
        );

        expect(result).toBe("<p>sanitized</p>");
        expect(mockDOMPurify.sanitize).toHaveBeenCalledWith(
          "<script>evil</script><p>good</p>",
          {
            ...STRICT_HTML_POLICY_CONFIG,
            RETURN_TRUSTED_TYPE: false,
          },
        );
      });

      it("throws InvalidConfigurationError for unknown policy", () => {
        expect(() => sanitizer.getSanitizedString("html", "unknown")).toThrow(
          InvalidConfigurationError,
        );
      });
    });
  });

  describe("integration scenarios", () => {
    it("handles XSS attack vectors", () => {
      const policies = { strict: STRICT_HTML_POLICY_CONFIG };
      const sanitizer = new Sanitizer(mockDOMPurify, policies);

      mockDOMPurify.sanitize.mockReturnValue("<p>safe content</p>");

      const maliciousHtml =
        '<script>alert("xss")</script><img src=x onerror=alert(1)><p>safe</p>';
      const result = sanitizer.sanitizeForNonTTBrowsers(
        maliciousHtml,
        "strict",
      );

      expect(mockDOMPurify.sanitize).toHaveBeenCalledWith(maliciousHtml, {
        ...STRICT_HTML_POLICY_CONFIG,
        RETURN_TRUSTED_TYPE: false,
      });
      expect(result).toBe("<p>safe content</p>");
    });

    it("handles SVG content with hardened policy", () => {
      const policies = { svg: HARDENED_SVG_POLICY_CONFIG };
      const sanitizer = new Sanitizer(mockDOMPurify, policies);

      mockDOMPurify.sanitize.mockReturnValue(
        '<svg><circle cx="50" cy="50" r="40"/></svg>' as any,
      );

      const svgContent =
        '<svg><script>alert(1)</script><circle cx="50" cy="50" r="40"/></svg>';
      const result = sanitizer.sanitizeForNonTTBrowsers(svgContent, "svg");

      expect(mockDOMPurify.sanitize).toHaveBeenCalledWith(svgContent, {
        ...HARDENED_SVG_POLICY_CONFIG,
        RETURN_TRUSTED_TYPE: false,
      });
    });
  });
});
