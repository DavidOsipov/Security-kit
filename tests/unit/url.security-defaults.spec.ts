import { describe, it, expect } from "vitest";
import { validateURL, createSecureURL } from "../../src/url";

describe("url security defaults and options", () => {
  it("requires HTTPS by default in validateURL", () => {
    const res = validateURL("http://example.test/path");
    expect(res.ok).toBe(false);
  });

  it("rejects http even when allowedSchemes includes 'http:' (HTTPS-only policy)", () => {
    const res = validateURL("http://example.test/path", {
      allowedSchemes: ["http:", "https:"],
    });
    expect(res.ok).toBe(false);
  });

  it("empty allowedOrigins array denies all origins", () => {
    const res = validateURL("https://example.test/path", {
      allowedOrigins: [],
    });
    expect(res.ok).toBe(false);
  });

  it("createSecureURL rejects fragments with control characters", () => {
    expect(() =>
      createSecureURL("https://example.test", [], {}, "bad\x01frag"),
    ).toThrow();
  });

  it("createSecureURL rejects disallowed schemes by default", () => {
    expect(() =>
      createSecureURL("javascript:alert(1)" as unknown as string),
    ).toThrow();
  });
});
