import { describe, it, expect } from "vitest";
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  parseURLParams,
  encodeComponentRFC3986,
  strictDecodeURIComponent,
} from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("url module", () => {
  it("createSecureURL builds URL and encodes params", () => {
    const res = createSecureURL("https://example.com", ["api", "v1"], { q: "a b" });
    expect(res.startsWith("https://example.com/")).toBe(true);
    expect(res.includes("q=a%20b") || res.includes("q=a+b")).toBe(true);
  });

  it("createSecureURL accepts plain null-prototype params and encodes them", () => {
    const params = Object.create(null) as Record<string, unknown>;
    params.safe = "1";
    const res = createSecureURL("https://example.com", [], params as any);
    expect(res.includes("safe=1")).toBe(true);
  });

  it("updateURLParams can remove undefined and set values", () => {
    const base = "https://example.com/?a=1&b=2";
    const updated = updateURLParams(base, { a: undefined, b: "x", c: "z" }, { removeUndefined: true, onUnsafeKey: "throw" });
    expect(updated.includes("a=")).toBe(false);
    expect(updated.includes("b=x")).toBe(true);
    expect(updated.includes("c=z")).toBe(true);
  });

  it("validateURL rejects bad schemes", () => {
    const res = validateURL("javascript:alert(1)");
    expect(res.ok).toBe(false);
  });

  it("parseURLParams returns frozen safe object and warns on missing", () => {
    const obj = parseURLParams("https://example.com/?a=1&b=2");
    expect(Object.isFrozen(obj)).toBe(true);
    expect((obj as any).a).toBe("1");
  });

  it("strictDecodeURIComponent returns error on malformed", () => {
    const r = strictDecodeURIComponent("%E0%A4%A");
    expect(r.ok).toBe(false);
  });
});
