import { normalizeOrigin, validateURL } from "../../src/url";
import { expect, it, describe } from "vitest";

describe("normalizeOrigin extra cases", () => {
  it("strips default https port 443", () => {
    const a = normalizeOrigin("https://example.com:443");
    const b = normalizeOrigin("https://example.com");
    expect(a).toBe(b);
  });

  it("strips default http port 80", () => {
    const a = normalizeOrigin("http://example.com:80");
    const b = normalizeOrigin("http://example.com");
    expect(a).toBe(b);
  });

  it("preserves non-default ports", () => {
    const a = normalizeOrigin("https://example.com:8443");
    expect(a).toBe("https://example.com:8443");
  });

  it("handles trailing slash consistently", () => {
    const a = normalizeOrigin("https://example.com/");
    const b = normalizeOrigin("https://example.com");
    expect(a).toBe(b);
  });

  it("normalizes localhost with port", () => {
    const a = normalizeOrigin("http://localhost:3000");
    const b = normalizeOrigin("http://localhost:3000/");
    expect(a).toBe(b);
  });

  it("validateURL allowlist matches normalized origins", () => {
    const allowlist = ["https://example.com"];
    expect(
      validateURL("https://example.com:443/path", { allowedOrigins: allowlist })
        .ok,
    ).toBe(true);
    expect(
      validateURL("https://example.com/", { allowedOrigins: allowlist }).ok,
    ).toBe(true);
    expect(
      validateURL("https://example.com:8443/", { allowedOrigins: allowlist })
        .ok,
    ).toBe(false);
  });
});
