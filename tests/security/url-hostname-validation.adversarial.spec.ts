// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Comprehensive adversarial tests for hostname validation in URL utilities.
 *
 * Tests RFC 1123 compliance, edge cases, and adversarial inputs to ensure
 * the library rejects invalid hostnames while accepting valid ones.
 *
 * OWASP ASVS v5 V1.2.2: Validates untrusted data in URL contexts.
 * Security Constitution: Verifiable Security - tests prove hostname validation.
 */

import { describe, it, expect } from "vitest";
import { InvalidParameterError } from "../../src/errors";
import {
  normalizeOrigin,
  createSecureURL,
  updateURLParams,
  validateURL,
  parseURLParams,
} from "../../src/url";

describe("URL Hostname Validation - Adversarial Tests", () => {
  describe("Invalid Hostname Cases", () => {
    const invalidHostnames = [
      "example!.com", // disallowed punctuation
      "exämple.com", // raw unicode (depends on punycode conversion)
      "-bad.com", // leading hyphen
      "bad-.com", // trailing hyphen
      "a..b", // empty label
      "a".repeat(64) + ".com", // label too long (>63)
      "a".repeat(254) + ".com", // FQDN too long (>253)
      "example..com", // consecutive dots
      "example.com-", // trailing hyphen in label
      "-example.com", // leading hyphen in label
      "192.168.1.256", // invalid IPv4 octet
      "192.168.1.1.1", // too many IPv4 octets
      "[::1", // incomplete IPv6
      "::1]", // misplaced bracket
      "[invalid]", // invalid IPv6
      "", // empty hostname
      " ", // whitespace only
      "example.com\t", // control char
      "exa mple.com", // internal space
      "%65xample.com", // percent encoding in host
      "example.com/extra", // slash in host string when passed raw
      "user:pass@example.com", // embedded credentials (should be rejected)
      "__proto__", // property name attack
    ];

    for (const hostname of invalidHostnames) {
      describe(`Invalid hostname: "${hostname}"`, () => {
        it("normalizeOrigin throws InvalidParameterError", () => {
          expect(() => normalizeOrigin(`https://${hostname}`)).toThrow(
            InvalidParameterError,
          );
        });

        const hasPathInHost = hostname.includes("/");
        if (hasPathInHost) {
          // In full URL context, a path after the authority is valid; only origin-only APIs reject it
          it("createSecureURL accepts full URL with path", () => {
            expect(() =>
              createSecureURL(`https://${hostname}`, [], {}, undefined, {}),
            ).not.toThrow();
          });

          it("updateURLParams accepts full URL with path", () => {
            expect(() =>
              updateURLParams(`https://${hostname}`, {}, {}),
            ).not.toThrow();
          });

          it("validateURL returns ok: true for full URL with path", () => {
            const result = validateURL(`https://${hostname}`);
            expect(result.ok).toBe(true);
          });

          it("parseURLParams accepts full URL with path", () => {
            expect(() => parseURLParams(`https://${hostname}`)).not.toThrow();
          });
        } else {
          it("createSecureURL throws InvalidParameterError", () => {
            expect(() =>
              createSecureURL(`https://${hostname}`, [], {}, undefined, {}),
            ).toThrow(InvalidParameterError);
          });

          it("updateURLParams throws InvalidParameterError", () => {
            expect(() =>
              updateURLParams(`https://${hostname}`, {}, {}),
            ).toThrow(InvalidParameterError);
          });

          it("validateURL returns ok: false", () => {
            const result = validateURL(`https://${hostname}`);
            expect(result.ok).toBe(false);
            if (!result.ok)
              expect(result.error).toBeInstanceOf(InvalidParameterError);
          });

          it("parseURLParams throws InvalidParameterError", () => {
            expect(() => parseURLParams(`https://${hostname}`)).toThrow(
              InvalidParameterError,
            );
          });
        }
      });
    }
  });

  describe("Valid and Ambiguous Hostname Cases", () => {
    // These cases exercise WHATWG permissive parsing and also our stricter checks.
    const cases = [
      { input: "example.com", valid: true, normalized: "example.com" },
      { input: "sub.example.com", valid: true, normalized: "sub.example.com" },
      { input: "EXAMPLE.COM", valid: true, normalized: "example.com" },
      { input: "example.com.", valid: true, normalized: "example.com" }, // trailing dot removed
      { input: "192.168.1.1", valid: true, normalized: "192.168.1.1" },
      { input: "192.168.1", valid: true, normalized: "192.168.1" }, // WHATWG accepts
      { input: "[::1]", valid: true, normalized: "[::1]" },
      { input: "[2001:db8::1]", valid: true, normalized: "[2001:db8::1]" },
      { input: "a-b.com", valid: true, normalized: "a-b.com" },
      { input: "example.com ", valid: true, normalized: "example.com" }, // trailing space trimmed by WHATWG
      {
        input: "xn--e1afmkfd.xn--p1ai",
        valid: true,
        normalized: "xn--e1afmkfd.xn--p1ai",
      }, // punycode for пример.рф
      {
        input: "xn--exa-mple.com",
        valid: true,
        normalized: "xn--exa-mple.com",
      }, // odd punycode-ish label
    ];

    for (const { input, valid, normalized } of cases) {
      describe(`Case: "${input}" (valid=${valid})`, () => {
        it("validateURL returns expected validity", () => {
          const r = validateURL(`https://${input}`);
          expect(r.ok).toBe(valid);
          if (r.ok) expect(r.url.hostname).toBe(normalized);
        });

        it("normalizeOrigin canonicalizes hostname when valid", () => {
          if (valid) {
            expect(normalizeOrigin(`https://${input}`)).toBe(
              `https://${normalized}`,
            );
          } else {
            expect(() => normalizeOrigin(`https://${input}`)).toThrow();
          }
        });

        it("createSecureURL respects validation", () => {
          if (valid) {
            const s = createSecureURL(
              `https://${input}`,
              [],
              {},
              undefined,
              {},
            );
            // trailing slash appended by createSecureURL for path
            expect(s.startsWith(`https://${normalized}`)).toBe(true);
          } else {
            expect(() =>
              createSecureURL(`https://${input}`, [], {}, undefined, {}),
            ).toThrow();
          }
        });
      });
    }
  });

  describe("Highly adversarial fuzz-like inputs", () => {
    const fuzzy = [
      // extremely long label then valid suffix
      "a".repeat(63) + "." + "b".repeat(63) + ".com",
      // labels that are only digits (allowed)
      "123.456.789.example",
      // label made of hyphens (invalid because start/end must be alnum)
      "---.com",
      // label contains null char encoded in string
      `evil\u0000.example`,
      // percent-encoded octets in host
      "example%2ecom",
      // embedded @ which could be confused for credentials
      "user@host.com",
    ];

    for (const h of fuzzy) {
      it(`fuzz input "${h}" should be rejected or handled safely`, () => {
        const res = validateURL(`https://${h}`);
        // Accept either ok:false (rejected) or ok:true but with a safe ASCII hostname.
        if (!res.ok) {
          expect(res.error).toBeInstanceOf(InvalidParameterError);
        } else {
          expect(typeof res.url.hostname).toBe("string");
          expect(res.url.hostname.length).toBeLessThanOrEqual(253);
        }
      });
    }
  });
});
