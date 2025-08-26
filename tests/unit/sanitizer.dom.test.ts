import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  Sanitizer,
  STRICT_HTML_POLICY_CONFIG,
  HARDENED_SVG_POLICY_CONFIG,
} from "../../src/sanitizer";
import { InvalidConfigurationError, InvalidParameterError } from "../../src/errors";

describe("Sanitizer (DOM & Trusted Types)", () => {
  let origWindow: any;
  beforeEach(() => {
    // Preserve any real window
    origWindow = (globalThis as any).window;
    if (!(globalThis as any).window) (globalThis as any).window = {};
  });
  afterEach(() => {
    // restore
    (globalThis as any).window = origWindow;
    vi.restoreAllMocks();
  });

  it("constructor validates dompurify instance", () => {
    expect(() => new Sanitizer(null as any, { strict: STRICT_HTML_POLICY_CONFIG })).toThrow(InvalidParameterError);
  });

  it("createPolicy throws for unknown policy name", () => {
    const dompurify = { sanitize: vi.fn() } as any;
    const s = new Sanitizer(dompurify, { strict: STRICT_HTML_POLICY_CONFIG });
    expect(() => s.createPolicy("missing")).toThrow(InvalidConfigurationError);
  });

  it("createPolicy creates and caches TrustedTypePolicy and calls DOMPurify when used", () => {
    const dompurify = { sanitize: vi.fn((s: string, cfg: any) => (cfg.RETURN_TRUSTED_TYPE ? ("<trusted>" as unknown) : "<sanitized>")) } as any;
    // Mock trustedTypes.createPolicy to capture rules
    const createPolicyMock = vi.fn((name: string, rules: any) => {
      // return an object exposing createHTML to simulate real policy
      return { name, createHTML: rules.createHTML } as any;
    });
    (globalThis as any).window.trustedTypes = { createPolicy: createPolicyMock };

    const policies = { strict: STRICT_HTML_POLICY_CONFIG, svg: HARDENED_SVG_POLICY_CONFIG };
    const s = new Sanitizer(dompurify, policies);

    const policy = s.createPolicy("strict");
    expect(createPolicyMock).toHaveBeenCalledWith("strict", expect.any(Object));
    // invoking createHTML should call DOMPurify.sanitize with RETURN_TRUSTED_TYPE true
  const trusted = (policy as any).createHTML("<b>x</b>");
  expect(dompurify.sanitize).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ RETURN_TRUSTED_TYPE: true }));
    // ensure caching: second call returns same identity
    const policy2 = s.createPolicy("strict");
    expect(policy2).toBe(policy);
  });

  it("sanitizeForNonTTBrowsers uses DOMPurify and returns string", () => {
    const dompurify = { sanitize: vi.fn((s: string, cfg: any) => "cleaned") } as any;
    const s = new Sanitizer(dompurify, { strict: STRICT_HTML_POLICY_CONFIG });
    const out = s.sanitizeForNonTTBrowsers("<b>bad</b>", "strict");
    expect(out).toBe("cleaned");
    expect(dompurify.sanitize).toHaveBeenCalledWith("<b>bad</b>", expect.objectContaining({ RETURN_TRUSTED_TYPE: false }));
  });

  it("createPolicyIfAvailable returns null when trustedTypes unavailable", () => {
    // Ensure no trustedTypes on window
    (globalThis as any).window.trustedTypes = undefined;
    const dompurify = { sanitize: vi.fn(() => "x") } as any;
    const s = new Sanitizer(dompurify, { strict: STRICT_HTML_POLICY_CONFIG });
    const res = s.createPolicyIfAvailable("strict");
    expect(res).toBeUndefined();
  });
});
