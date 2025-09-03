import { describe, it, expect } from "vitest";
import { createSecureURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("createSecureURL", () => {
  it("encodes path segments once (no double-encode)", () => {
    const href = createSecureURL("https://example.test", ["foo bar"]);
    expect(href).toBe("https://example.test/foo%20bar");
  });

  it("rejects traversal or separators in segments", () => {
    expect(() => createSecureURL("https://example.test", ["foo/bar"])).toThrow(
      InvalidParameterError,
    );
    expect(() => createSecureURL("https://example.test", [".."])).toThrow(
      InvalidParameterError,
    );
  });

  it("appends query params using URLSearchParams and preserves existing params", () => {
    const href = createSecureURL(
      "https://example.test/path?alpha=1",
      ["child"],
      { beta: 2, gamma: "x y" },
    );
    // Order of params can vary; assert presence and correct encoding
    expect(href.startsWith("https://example.test/path/child?")).toBe(true);
    const url = new URL(href);
    expect(url.searchParams.get("alpha")).toBe("1");
    expect(url.searchParams.get("beta")).toBe("2");
    expect(url.searchParams.get("gamma")).toBe("x y");
  });
});
