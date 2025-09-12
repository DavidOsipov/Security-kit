import { describe, it, expect, vi } from "vitest";
import { parseAndValidateFullURL, parseURLParams } from "../../src/url";

// Helper to stub getUrlHardeningConfig via dynamic import and vi.spyOn on the
// imported module. This avoids require() resolution issues in ESM contexts.
async function withTempConfigAsync<T>(patch: Record<string, unknown>, fn: () => Promise<T> | T): Promise<T> {
  // Import as module to obtain the same module instance used by src code
  const cfgModule = await import("../../src/config");
  const original = cfgModule.getUrlHardeningConfig();
  const spy = vi.spyOn(cfgModule, "getUrlHardeningConfig").mockImplementation(() => ({
    ...original,
    ...patch,
  }));
  try {
    return await fn();
  } finally {
    spy.mockRestore();
  }
}

describe("URL hardening tests", () => {
  it("handles authority at end of string (no path)", () => {
    const url = "https://example.com";
    expect(() => parseAndValidateFullURL(url, "test")).not.toThrow();
    const url2 = "https://example.com/";
    expect(() => parseAndValidateFullURL(url2, "test")).not.toThrow();
  });

  it("IDNA conversion enabled converts non-ASCII host", async () => {
    // Provide a mock idna provider on the runtime config
    await withTempConfigAsync(
      {
        enableIdnaToAscii: true,
        idnaProvider: {
          toASCII: (s: string) => {
            // naive mock: replace 'é' with 'e' and return a valid ascii host
            return s.replace(/é/g, "e");
          },
        },
      },
      () => {
        const url = "https://tést.example/";
        expect(() => parseAndValidateFullURL(url, "test")).not.toThrow();
      },
    );
  });

  it("IDNA disabled rejects non-ASCII authority", async () => {
    await withTempConfigAsync({ enableIdnaToAscii: false }, () => {
      const url = "https://tést.example/";
      expect(() => parseAndValidateFullURL(url, "test")).toThrow();
    });
  });

  it("parseURLParams returns frozen null-prototype object and filters keys", () => {
    const u = "https://example.com/?a=1&b=2&__proto__=polluted";
    const params = parseURLParams(u);
    expect(Object.isFrozen(params)).toBe(true);
    expect(Object.getPrototypeOf(params)).toBe(null);
    expect(params.a).toBe("1");
    expect(params.b).toBe("2");
    // Ensure prototype pollution attempt not reflected
    // @ts-ignore - intentionally check dynamic property
    expect((params as any).__proto__).toBeUndefined();
  });
});
