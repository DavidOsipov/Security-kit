import { describe, it, expect } from "vitest";
import { Sanitizer, STRICT_HTML_POLICY_CONFIG } from "../../src/sanitizer";
import { InvalidConfigurationError } from "../../src/errors";

describe("Sanitizer", () => {
  it("sanitizeForNonTTBrowsers returns sanitized string with known policy", () => {
    const mockDomPurify = {
      sanitize: (input: string, cfg?: any) => `SANITIZED:${input}`,
    } as any;

    const s = new Sanitizer(mockDomPurify, {
      strict: STRICT_HTML_POLICY_CONFIG,
    });
  const out = s.getSanitizedString("<b>hello</b>", "strict");
  expect(out).toBe("SANITIZED:<b>hello</b>");
  });

  it("createPolicy throws when policy missing", () => {
    const mockDomPurify = {
      sanitize: (_: string) => "",
    } as any;

    const s = new Sanitizer(mockDomPurify, {});
    expect(() => s.createPolicy("missing")).toThrow(InvalidConfigurationError);
  });
});
