import { describe, it, expect, beforeEach } from "vitest";

import {
  createSecureURL,
  validateURL,
  getEffectiveSchemes,
  encodeHostLabel,
  strictDecodeURIComponentOrThrow,
} from "../../src/url";
import {
  setRuntimePolicy,
  _resetUrlPolicyForTests,
  setUrlHardeningConfig,
  getUrlHardeningConfig,
  runWithStrictUrlHardening,
} from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

describe("url.adversarial - authority parsing & policy interactions", () => {
  beforeEach(() => {
    // Ensure policy is reset between tests
    _resetUrlPolicyForTests();
    // Reset other url hardening toggles for deterministic tests
    setUrlHardeningConfig({ forbidForbiddenHostCodePoints: true });
  });

  it("rejects IPv4 shorthand consistently", () => {
    expect(() => createSecureURL("https://192.168.1")).toThrow(
      InvalidParameterError,
    );
  });

  it("rejects percent-encoded authority early", () => {
    expect(() => createSecureURL("https://exa%25mple.com")).toThrow(
      InvalidParameterError,
    );
  });

  it("rejects embedded credentials even if WHATWG would parse", () => {
    expect(() => createSecureURL("https://user:pass@example.com")).toThrow(
      InvalidParameterError,
    );
  });

  it("enforces dangerous-fragment detection", () => {
    expect(() =>
      createSecureURL("https://example.com", [], {}, "javascript:alert(1)", {
        strictFragment: true,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("validateURL respects effective schemes and returns not-ok for deny-all", () => {
    const res = validateURL("https://example.com", { allowedSchemes: [] });
    expect(res.ok).toBe(false);
  });

  it("getEffectiveSchemes throws when caller list has no intersection (strict)", () => {
    // ensure strict runtime policy
    setRuntimePolicy({ allowCallerSchemesOutsidePolicy: false });
    expect(() => getEffectiveSchemes(["gopher:"])).toThrow(
      InvalidParameterError,
    );
  });

  it("getEffectiveSchemes returns caller set when runtime policy allows it", () => {
    setRuntimePolicy({ allowCallerSchemesOutsidePolicy: true });
    const set = getEffectiveSchemes(["gopher:"]);
    expect(set.has("gopher:")).toBe(true);
  });

  it("encodeHostLabel requires idna library", () => {
    expect(() => encodeHostLabel("xn--example", undefined as any)).toThrow();
  });

  it("strictDecodeURIComponentOrThrow throws on malformed", () => {
    expect(() => strictDecodeURIComponentOrThrow("%")).toThrow();
  });

  it("runWithStrictUrlHardening toggles strict IPv4 checks within block", () => {
    // explicitly flip flag to false, then ensure helper enables and restores it
    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: false });
    expect(getUrlHardeningConfig().strictIPv4AmbiguityChecks).toBe(false);
    runWithStrictUrlHardening(() => {
      expect(getUrlHardeningConfig().strictIPv4AmbiguityChecks).toBe(true);
    });
    // restored
    expect(getUrlHardeningConfig().strictIPv4AmbiguityChecks).toBe(false);
  });
});
