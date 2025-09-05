import { describe, it, expect } from "vitest";
import { createSecureURL, updateURLParams, validateURL } from "../../src/url";

describe("resource limiting", () => {
  it("createSecureURL rejects too many query params", () => {
    const base = "https://example.com/";
    const params: Record<string, unknown> = {};
    for (let i = 0; i < 300; i++) params[`k${i}`] = "v";

    expect(() =>
      createSecureURL(base, [], params, undefined, { maxQueryParameters: 256 }),
    ).toThrow();
  });

  it("updateURLParams rejects final param count too large", () => {
    const base = "https://example.com/?a=1&b=2";
    const updates: Record<string, unknown> = {};
    for (let i = 0; i < 300; i++) updates[`k${i}`] = "v";

    expect(() =>
      updateURLParams(base, updates, { maxQueryParameters: 256 }),
    ).toThrow();
  });

  it("validateURL rejects URLs with too many params", () => {
    const url =
      "https://example.com/?" +
      Array.from({ length: 300 }, (_, i) => `k${i}=v`).join("&");
    expect(validateURL(url, { maxQueryParameters: 256 }).ok).toBe(false);
  });
});
