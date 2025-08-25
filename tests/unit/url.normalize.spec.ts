import { describe, it, expect } from "vitest";
import { validateURL } from "../../src/url";

describe("validateURL origin normalization", () => {
  it("accepts default-port variation when allowlist contains normalized origin", () => {
    const res = validateURL("https://example.com:443/path", {
      allowedOrigins: ["https://example.com"],
    });
    expect(res.ok).toBe(true);
  });

  it("rejects origins not in allowlist", () => {
    const res = validateURL("https://evil.example.com/path", {
      allowedOrigins: ["https://example.com"],
    });
    expect(res.ok).toBe(false);
  });
});
