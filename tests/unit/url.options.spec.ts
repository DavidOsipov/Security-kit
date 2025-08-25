import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURLStrict,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("URL options hardening", () => {
  it("throws when onUnsafeKey='throw' and unsafe key provided", () => {
    const base = "https://example.com/";
    const params: Record<string, unknown> = Object.create(null);
    // create an actual own property named '__proto__'
    (params as any)["__proto__"] = "x";
    expect(() =>
      createSecureURL(base, [], params, undefined, { onUnsafeKey: "throw" }),
    ).toThrow(InvalidParameterError);
  });

  it("skips unsafe key when onUnsafeKey='skip'", () => {
    const base = "https://example.com/";
    const href = createSecureURL(
      base,
      [],
      { bad: "1", __proto__: "x" },
      undefined,
      { onUnsafeKey: "skip" },
    );
    expect(href).toContain("bad=1");
    expect(href).not.toContain("__proto__");
  });

  it("enforces requireHTTPS in createSecureURL", () => {
    const base = "http://example.com/";
    expect(() =>
      createSecureURL(base, [], {}, undefined, { requireHTTPS: true }),
    ).toThrow(InvalidParameterError);
  });

  it("enforces maxLength in createSecureURL", () => {
    const base = "https://example.com/";
    const longParam = "a".repeat(3000);
    expect(() =>
      createSecureURL(base, [], { p: longParam }, undefined, { maxLength: 10 }),
    ).toThrow(InvalidParameterError);
  });

  it("updateURLParams obeys requireHTTPS and maxLength", () => {
    const url = "http://example.com/?a=1";
    expect(() =>
      updateURLParams(url, { b: "2" }, { requireHTTPS: true }),
    ).toThrow(InvalidParameterError);
    expect(() =>
      updateURLParams("https://example.com/", { x: "y" }, { maxLength: 1 }),
    ).toThrow(InvalidParameterError);
  });

  it("validateURLStrict requires HTTPS", () => {
    const res = validateURLStrict("http://example.com/");
    expect(res.ok).toBe(false);
  });
});
