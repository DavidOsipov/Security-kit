import { describe, it, expect, afterEach } from "vitest";
import { getEffectiveSchemes } from "../../src/url";
import { setRuntimePolicy, getRuntimePolicy } from "../../src/config";
import { configureUrlPolicy, _resetUrlPolicyForTests } from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

describe("getEffectiveSchemes policy semantics", () => {
  afterEach(() => {
    // Reset policy to defaults between tests
    _resetUrlPolicyForTests();
  });

  it("returns default safe schemes when allowedSchemes is undefined", () => {
    const s = getEffectiveSchemes();
    expect(s.has("https:")).toBe(true);
  });

  it("returns intersection when allowedSchemes overlaps policy", () => {
    // configureUrlPolicy default is https:, but callers may request http: and https:
    const s = getEffectiveSchemes(["http:", "https:"]);
    // intersection should contain https: but not http:
    expect(s.has("https:")).toBe(true);
    expect(s.has("http:")).toBe(false);
  });

  it("throws when allowedSchemes has no intersection with policy (strict default)", () => {
    expect(() => getEffectiveSchemes(["http:"])).toThrow(InvalidParameterError);
  });

  it("respects caller-provided schemes when runtime policy enables permissive mode", () => {
    const prev = getRuntimePolicy();
    setRuntimePolicy({ allowCallerSchemesOutsidePolicy: true });
    try {
      const s = getEffectiveSchemes(["http:"]);
      expect(s.has("http:")).toBe(true);
    } finally {
      setRuntimePolicy({
        allowCallerSchemesOutsidePolicy: prev.allowCallerSchemesOutsidePolicy,
      });
    }
  });

  it("allows explicit configuration via configureUrlPolicy and reflects in intersection", () => {
    configureUrlPolicy({ safeSchemes: ["http:", "https:"] });
    const s = getEffectiveSchemes(["http:"]);
    expect(s.has("http:")).toBe(true);
  });
});
