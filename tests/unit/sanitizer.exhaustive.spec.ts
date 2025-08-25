import { describe, it, expect, afterEach } from "vitest";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG, HARDENED_SVG_POLICY_CONFIG } from "../../src/sanitizer";
import { InvalidConfigurationError } from "../../src/errors";

// Minimal DOMPurify-like stub for tests
function makeDP(returnTrusted = false) {
  return {
    sanitize(s: string, cfg?: any) {
      // echo input with marker preventing accidental HTML interpretation
      if (cfg && cfg.RETURN_TRUSTED_TYPE && returnTrusted) {
        // create a fake TrustedHTML via a symbol wrapper
        return (`[TRUSTED]${s}`) as unknown as TrustedHTML;
      }
      return s.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },
  };
}

const savedWindow = (global as any).window;

afterEach(() => {
  // Restore window to avoid test pollution
  (global as any).window = savedWindow;
});

describe("Sanitizer exhaustive tests", () => {
  it("throws if invalid dompurify instance provided", () => {
    expect(() => new (Sanitizer as any)(null, { strict: STRICT_HTML_POLICY_CONFIG })).toThrow();
  });

  it("sanitizeForNonTTBrowsers returns sanitized string and enforces config existence", () => {
    const dp = makeDP(false);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG });
    const out = s.sanitizeForNonTTBrowsers("<b>hi</b>", "strict");
    expect(out).toBe("&lt;b&gt;hi&lt;/b&gt;");
    expect(() => s.sanitizeForNonTTBrowsers("x", "missing")).toThrow(InvalidConfigurationError);
  });

  it("createPolicyIfAvailable returns null when window undefined or trustedTypes absent", () => {
    delete (global as any).window;
    const dp = makeDP(true);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG });
    expect(s.createPolicyIfAvailable("strict")).toBeNull();

    (global as any).window = {};
    expect(s.createPolicyIfAvailable("strict")).toBeNull();
  });

  it("createPolicy succeeds when trustedTypes.createPolicy exists and policy create returns TrustedHTML", () => {
    const dp = makeDP(true);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG });

    // mock trustedTypes.createPolicy
    const created: any = {};
    (global as any).window = {
      trustedTypes: {
        createPolicy(name: string, rules: any) {
          // call createHTML to ensure sanitize path is exercised
          const res = rules.createHTML("<ok>");
          created[name] = res;
          return ({ create: rules.createHTML } as unknown) as any as TrustedTypePolicy;
        },
      },
    };

    const p = s.createPolicy("strict");
  expect(typeof (p as any).create).toBe("function");
  // calling create should return our fake TrustedHTML string marker
  const v = (p as any).create("<x>");
  expect(String(v)).toContain("[TRUSTED]");

    // subsequent createPolicy call returns cached instance (same ref)
    const p2 = s.createPolicy("strict");
    expect(p2).toBe(p);
  });

  it("createPolicy throws if policy name not defined or trustedTypes missing", () => {
    const dp = makeDP(true);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG });
    // No trustedTypes
    (global as any).window = {};
    expect(() => s.createPolicy("strict")).toThrow();

    // undefined policy
    (global as any).window = { trustedTypes: { createPolicy: () => ({}) } };
    expect(() => s.createPolicy("missing")).toThrow(InvalidConfigurationError);
  });

  it("createPolicyIfAvailable falls back to null when createPolicy throws", () => {
    const dp = makeDP(true);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG });
    (global as any).window = {
      trustedTypes: {
        createPolicy(_name: string) {
          throw new Error("boom");
        },
      },
    };
    const p = s.createPolicyIfAvailable("strict");
    expect(p).toBeNull();
  });

  it("getSanitizedString delegates to sanitizeForNonTTBrowsers and handles different policies", () => {
    const dp = makeDP(false);
    const s = new Sanitizer(dp as any, { strict: STRICT_HTML_POLICY_CONFIG, svg: HARDENED_SVG_POLICY_CONFIG });
    const out1 = s.getSanitizedString("<img onerror=1>", "svg");
    expect(out1).toContain("&lt;img");
    const out2 = s.getSanitizedString("<b>ok</b>", "strict");
    expect(out2).toContain("&lt;b&gt;ok&lt;/b&gt;");
  });
});
