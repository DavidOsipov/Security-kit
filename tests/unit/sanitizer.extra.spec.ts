import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG, HARDENED_SVG_POLICY_CONFIG } from "../../src/sanitizer";
import { InvalidConfigurationError, InvalidParameterError } from "../../src/errors";

// Minimal DOMPurify-like stub
const goodDomPurify = {
  sanitize: (s: string, cfg?: any) => {
    // Simulate returning TrustedHTML when RETURN_TRUSTED_TYPE true
    if (cfg && cfg.RETURN_TRUSTED_TYPE) return (s as unknown) as TrustedHTML;
    return s.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  },
};

const badDomPurify = { sanitize: "not-a-function" } as any;

describe("Sanitizer core behaviors", () => {
  it("constructor throws on invalid dompurify instance", () => {
    expect(() => new Sanitizer(badDomPurify, { strict: STRICT_HTML_POLICY_CONFIG })).toThrow(InvalidParameterError);
  });

  it("sanitizeForNonTTBrowsers applies config and removes script tags", () => {
    const s = new Sanitizer(goodDomPurify as any, { strict: STRICT_HTML_POLICY_CONFIG });
    const out = s.sanitizeForNonTTBrowsers('<b>ok</b><script>alert(1)</script>', 'strict');
    expect(out).toBe('<b>ok</b>');
  });

  describe("Trusted Types policy creation", () => {
    let origWindow: any;
    beforeEach(() => {
      origWindow = (globalThis as any).window;
      (globalThis as any).window = {};
    });
    afterEach(() => {
      (globalThis as any).window = origWindow;
    });

    it("createPolicyIfAvailable returns null when Trusted Types not present", () => {
      const s = new Sanitizer(goodDomPurify as any, { strict: STRICT_HTML_POLICY_CONFIG });
      expect(s.createPolicyIfAvailable('strict')).toBeNull();
    });

    it("createPolicyIfAvailable creates and returns policy when available", () => {
      const created: any = {};
      (globalThis as any).window.trustedTypes = {
        createPolicy: (name: string, rules: any) => {
          created[name] = rules;
          return { name } as TrustedTypePolicy;
        },
      };
      const s = new Sanitizer(goodDomPurify as any, { strict: STRICT_HTML_POLICY_CONFIG });
      const p = s.createPolicyIfAvailable('strict');
      expect(p).toBeTruthy();
      // second call returns cached policy
      const p2 = s.createPolicyIfAvailable('strict');
      expect(p2).toBe(p);
    });

    it("createPolicy throws when policy name unknown", () => {
      (globalThis as any).window.trustedTypes = { createPolicy: () => ({}) };
      const s = new Sanitizer(goodDomPurify as any, { strict: STRICT_HTML_POLICY_CONFIG });
      expect(() => s.createPolicy('missing')).toThrow(InvalidConfigurationError);
    });
  });
});
