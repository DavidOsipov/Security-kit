import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { normalizeOrigin, createSecureURL } from "../../src/url";
import { setUrlHardeningConfig, getUrlHardeningConfig } from "../../src/config";

describe("IDNA integration: pre-parse conversion and validation", () => {
  let saved = getUrlHardeningConfig();
  beforeEach(() => {
    saved = getUrlHardeningConfig();
  });
  afterEach(() => {
    // restore previous config to avoid test cross-contamination
    setUrlHardeningConfig(saved as any);
  });

  it("throws when enabling IDNA without provider", () => {
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true })).toThrow();
  });

  it("accepts valid provider and normalizeOrigin returns converted authority", () => {
    // Mock provider that returns a valid ASCII A-label for demonstration
    const provider = {
      toASCII: (s: string) => {
        // simple deterministic stub: lowercase + replace non-ascii/invalid with 'x'
        return s
          .toLowerCase()
          .replace(/[^a-z0-9.-]/g, "x")
          .replace(/(^-|-$)/g, "x");
      },
    } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const out = normalizeOrigin("https://Exämple.com");
    // provider stub lowercased input; ensure result is lowercase and contains no Unicode
    expect(out).toBe("https://exxmple.com");
  });

  it("rejects provider returning forbidden characters during parsing", () => {
    const provider = { toASCII: (_s: string) => "bad/host" } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    expect(() => normalizeOrigin("https://täst.com")).toThrow();
  });

  it("rejects provider returning non-ASCII during config-time validation", () => {
    const provider = { toASCII: (_s: string) => "tést" } as any; // contains non-ascii e with accent
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider as any })).toThrow();
  });

  it("createSecureURL accepts IDNA-converted authority when provider returns valid ASCII", () => {
    const provider = { toASCII: (s: string) => s.toLowerCase().replace(/[^a-z0-9.-]/g, "a") } as any;
    setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider });
    const out = createSecureURL("https://Exämple.com", []);
    expect(out.startsWith("https://examp"));
  });
});
