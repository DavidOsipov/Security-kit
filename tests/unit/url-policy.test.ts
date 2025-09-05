import { describe, it, expect, beforeEach } from "vitest";
import {
  configureUrlPolicy,
  getSafeSchemes,
  _resetUrlPolicyForTests,
} from "../../src/config";
import {
  InvalidParameterError,
  InvalidConfigurationError,
} from "../../src/errors";

describe("url-policy", () => {
  beforeEach(() => {
    try {
      _resetUrlPolicyForTests();
    } catch {}
  });

  it("returns default safe scheme initially", () => {
    const schemes = getSafeSchemes();
    expect(schemes).toContain("https:");
  });

  it("configureUrlPolicy accepts valid custom schemes", () => {
    configureUrlPolicy({ safeSchemes: ["https:", "custom:"] });
    const schemes = getSafeSchemes();
    expect(schemes).toContain("custom:");
  });

  it("configureUrlPolicy rejects empty or non-array inputs", () => {
    // @ts-ignore - test runtime validation
    expect(() => configureUrlPolicy({ safeSchemes: [] })).toThrow(
      InvalidParameterError,
    );
    // @ts-ignore
    expect(() => configureUrlPolicy({ safeSchemes: "not-an-array" })).toThrow(
      InvalidParameterError,
    );
  });

  it("configureUrlPolicy rejects forbidden schemes like javascript:", () => {
    expect(() =>
      configureUrlPolicy({ safeSchemes: ["https:", "javascript:"] }),
    ).toThrow(InvalidParameterError);
  });
});
