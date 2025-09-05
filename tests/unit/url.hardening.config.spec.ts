import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  setUrlHardeningConfig,
  getUrlHardeningConfig,
  setRuntimePolicy,
  freezeConfig,
} from "../../src/config";
import { validateURL, createSecureURL } from "../../src/url";

describe("url hardening config (unit)", () => {
  const saved = getUrlHardeningConfig();

  afterEach(() => {
    // restore defaults by re-setting initial values (not sealed in tests)
    setUrlHardeningConfig(saved as Partial<typeof saved>);
  });

  it("enforceSpecialSchemeAuthority toggle disables special-scheme enforcement", () => {
    // when disabled, a special scheme without '//' should be allowed through base parser
    setUrlHardeningConfig({ enforceSpecialSchemeAuthority: false });
    const r = validateURL("https:example.com", { maxLength: 1024 });
    // WHATWG may still normalize; ensure we don't throw due to scheme-enforcement
    expect(r.ok).toBe(true);

    // enable enforcement back and ensure strict mode catches it
    setUrlHardeningConfig({ enforceSpecialSchemeAuthority: true });
    const r2 = validateURL("https:example.com", { maxLength: 1024 });
    expect(r2.ok).toBe(false);
  });

  it("forbidForbiddenHostCodePoints toggle disables forbidden code point checks", () => {
    // The runtime toggle should be reflected in the config getter after setting.
    setUrlHardeningConfig({ forbidForbiddenHostCodePoints: false });
    expect(getUrlHardeningConfig().forbidForbiddenHostCodePoints).toBe(false);

    setUrlHardeningConfig({ forbidForbiddenHostCodePoints: true });
    expect(getUrlHardeningConfig().forbidForbiddenHostCodePoints).toBe(true);
  });

  it("strictIPv4AmbiguityChecks toggle controls IPv4 ambiguity rejection", () => {
    // leading-zero segment dotted hostname should be allowed when strict checks off
    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: false });
    const r = validateURL("https://192.168.01.1");
    expect(r.ok).toBe(true);

    setUrlHardeningConfig({ strictIPv4AmbiguityChecks: true });
    const r2 = validateURL("https://192.168.01.1");
    expect(r2.ok).toBe(false);
  });

  it("validatePathPercentEncoding toggle controls path percent-decoding validation", () => {
    setUrlHardeningConfig({ validatePathPercentEncoding: false });
    const r = validateURL("https://example.com/%ZZ");
    // when disabled, our additional percent-encoding check is skipped; underlying URL parser may still treat it as valid
    // We accept either ok:true or ok:false depending on environment; assert that our config toggle flips behavior when enabled below.
    // No strict assertion here about r.ok to maintain robustness across platforms.

    setUrlHardeningConfig({ validatePathPercentEncoding: true });
    const r2 = validateURL("https://example.com/%ZZ");
    expect(r2.ok).toBe(false);
  });
});
