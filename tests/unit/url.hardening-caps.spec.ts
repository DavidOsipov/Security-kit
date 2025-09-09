import { describe, it, expect, afterEach } from "vitest";
import { createSecureURL, validateURL } from "../../src/url";
import {
  getUrlHardeningConfig,
  setUrlHardeningConfig,
} from "../../src/config";
import { InvalidParameterError } from "../../src/errors";

describe("URL hardening: bidi controls and per-parameter caps", () => {
  const saved = getUrlHardeningConfig();

  afterEach(() => {
    setUrlHardeningConfig(saved as any);
  });

  it("rejects or sanitizes authority containing U+061C (Arabic Letter Mark) and U+00AD (Soft Hyphen)", () => {
    const badAuthorityALM = "ex\u061Camp\u006C\u0065.com"; // insert ALM
    const badAuthoritySHY = "ex\u00ADample.com"; // insert soft hyphen

    for (const host of [badAuthorityALM, badAuthoritySHY]) {
      const input = `https://${host}/path`;
      let threw = false;
      try {
        const u = createSecureURL(input);
        const out = u.toString();
        // If not thrown, ensure output does not contain the disallowed controls
        expect(/[\u061C\u00AD]/.test(out)).toBe(false);
      } catch (e) {
        threw = true;
        expect(e).toBeInstanceOf(InvalidParameterError);
      }
      // validateURL returns a result object; expect ok=false OR sanitized output
      const result = validateURL(input);
      if (result.ok) {
        const out = result.url.toString();
        expect(/[\u061C\u00AD]/.test(out)).toBe(false);
      } else {
        expect(result.error).toBeInstanceOf(InvalidParameterError);
      }
    }
  });

  it("enforces maxQueryParamNameLength and maxQueryParamValueLength when adding params", () => {
    setUrlHardeningConfig({ maxQueryParamNameLength: 4, maxQueryParamValueLength: 8 });

    // Name too long (appended via queryParameters argument)
    expect(() =>
      createSecureURL("https://example.com/", [], { abcdef: 1 }),
    ).toThrow(InvalidParameterError);

    // Value too long
    expect(() =>
      createSecureURL("https://example.com/", [], { a: "0123456789" }),
    ).toThrow(InvalidParameterError);

    // Valid within limits
    const ok = createSecureURL("https://example.com/", [], { key: "1234" });
    expect(ok.toString()).toContain("?key=1234");
  });
});
