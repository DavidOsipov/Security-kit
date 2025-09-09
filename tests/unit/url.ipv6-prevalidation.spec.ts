// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { validateURL, createSecureURL } from "../../src/url";
import { InvalidParameterError } from "../../src/errors";

// Explicit unit tests for invalid bracketed IPv6 authorities now rejected
// early by preValidateBracketedIPv6Authority.

describe("IPv6 bracketed authority pre-validation", () => {
  const invalidUrls = [
    // Multiple closing brackets
    "https://[::1]]:80",
    // Empty inside brackets
    "https://[]",
    "https://[]:80",
    // Invalid characters after ']' (must be optional ':' then digits)
    "https://[::1]x8080",
    // Empty port
    "https://[::1]:",
    // Non-numeric port
    "https://[::1]:8a",
    // Port too long (>5 digits)
    "https://[::1]:123456",
    // Invalid character inside IPv6 literal
    "https://[::z]:80",
  ];

  for (const url of invalidUrls) {
    it(`rejects invalid bracketed IPv6: ${url}`, () => {
      const res = validateURL(url);
      expect(res.ok).toBe(false);
      expect(() => createSecureURL(url)).toThrow(InvalidParameterError);
    });
  }

  it("accepts valid bracketed IPv6 with port", () => {
    const res = validateURL("https://[2001:db8::1]:443");
    expect(res.ok).toBe(true);
  });
});
