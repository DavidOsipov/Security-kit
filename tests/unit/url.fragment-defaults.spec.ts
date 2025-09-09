import { describe, it, expect } from "vitest";
import { createSecureURL, validateURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

describe("URL fragments: strict defaults and no carryover", () => {
  it("does not carry over base fragment when fragment arg is undefined", () => {
    const href = createSecureURL("https://example.test/path#frag", ["x"]);
    expect(href).toBe("https://example.test/path/x");
  });

  it("encodes fragment with RFC3986 when provided and strict", () => {
    const href = createSecureURL(
      "https://example.test/path",
      ["x"],
      {},
      "spaces and#hash",
      { strictFragment: true },
    );
    expect(href).toBe(
      "https://example.test/path/x#spaces%20and%23hash",
    );
  });

  it("validateURL rejects dangerous schemes and malformed path percent-encoding", () => {
    const bad = validateURL("javascript:alert(1)");
    expect(bad.ok).toBe(false);

    const malformed = validateURL("https://example.test/%E0%A4%A");
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) {
      expect(malformed.error).toBeInstanceOf(InvalidParameterError);
    }
  });
});
