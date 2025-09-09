// tests/security/input-validation.adversarial.spec.ts
// Comprehensive adversarial tests for input validation, aligned with OWASP ASVS L3
// Focus: Unicode obfuscation, type juggling, encoding attacks, and canonicalization bypasses

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSecureURL,
  validateURL,
  normalizeOrigin,
} from "../../src/url";
import { toCanonicalValue, safeStableStringify } from "../../src/canonical";
import { InvalidParameterError } from "../../src/errors";
import { __test_toNullProto } from "../../src/postMessage";

describe("Input Validation - Adversarial Attacks (OWASP ASVS L3)", () => {
  describe("Unicode & Encoding Obfuscation Attacks", () => {
    it("should reject Unicode homoglyphs in URL origins", () => {
      const legitimateOrigin = "https://apple.com";
      // Cyrillic 'а' looks identical to Latin 'a'
      const maliciousOrigin = "https://аpple.com";

      // Under strict Option A (no implicit IDNA), raw Unicode authority must be rejected.
      expect(() => normalizeOrigin(maliciousOrigin)).toThrow(InvalidParameterError);

      // Validation must use canonical form
      const validation = validateURL(maliciousOrigin, {
        allowedOrigins: [legitimateOrigin],
      });
      expect(validation.ok).toBe(false);
      if (!validation.ok) {
        // With strict Option A policy, the failure is due to non-ASCII authority rejection.
        expect(validation.error.message).toContain("Raw non-ASCII characters");
      }
    });

    it("should reject double-encoded path traversal", () => {
      // %252E is double-encoded '.', becomes '.' after one decode
      const traversalPath = ["..%252E..%252Fetc%252Fpasswd"];
      expect(() =>
        createSecureURL("https://example.com/api/", traversalPath)
      ).toThrow(InvalidParameterError);
    });

    it("should reject overlong UTF-8 sequences", () => {
      // Overlong UTF-8 for '/' (U+002F)
      const overlongSlash = "\xC0\xAF"; // 2-byte overlong for '/'
      expect(() =>
        createSecureURL(`https://example.com${overlongSlash}admin`)
      ).toThrow(InvalidParameterError);
    });

    it("should handle mixed encoding in query parameters", () => {
      // Test with malformed query parameters
      const maliciousParams = { param: "%22<script>%22%<script>" };
      expect(() =>
        createSecureURL("https://example.com", [], maliciousParams)
      ).toThrow(InvalidParameterError);
    });
  });

  describe("Type Juggling & Prototype Manipulation", () => {
    it("should prevent malicious toJSON execution during canonicalization", () => {
      const maliciousPayload = {
        a: 1,
        toJSON: () => {
          (globalThis as any).wasToJSONCalled = true;
          return { hacked: true };
        },
      };

      const canonical = toCanonicalValue(maliciousPayload);

      // Side effect should never happen
      expect((globalThis as any).wasToJSONCalled).toBeUndefined();

      // Canonical form should be based on actual properties
      expect(canonical).toEqual({ a: 1 });
    });

    it("should handle objects with non-standard prototypes", () => {
      const customProto = { customProp: "evil" };
      const obj = Object.create(customProto);
      obj.safeProp = "good";

      const canonical = toCanonicalValue(obj);

      // Should not inherit prototype properties
      expect(canonical).toEqual({ safeProp: "good" });
      expect((canonical as any).customProp).toBeUndefined();
    });

  it("should sanitize objects with forbidden constructor properties", () => {
      const malicious = {
        constructor: {
          prototype: {
            polluted: true,
          },
        },
      };
      const canon = toCanonicalValue(malicious) as Record<string, unknown>;
      // Forbidden constructor/prototype must be dropped, no throw
      expect(canon).toEqual({});
    });

    it("should handle arrays with prototype manipulation", () => {
      const arr = [1, 2, 3];
      arr.constructor.prototype.malicious = "injected";

      const canonical = toCanonicalValue(arr) as unknown as { malicious?: string };

      // Should not include prototype pollution
      expect(Array.isArray(canonical)).toBe(true);
      expect(canonical).toEqual([1, 2, 3]);
      expect(canonical.malicious).toBeUndefined();
    });
  });

  describe("Canonicalization Edge Cases", () => {
    it("should detect and handle circular references safely", () => {
      const obj: any = { a: 1 };
      obj.self = obj;

      const canonical = toCanonicalValue(obj) as Record<string, unknown>;

      // Should detect circular reference at the top-level marker
      expect(canonical).toHaveProperty("__circular");
    });

  it("should throw typed error on depth exhaustion for deeply nested objects", () => {
      const deepObj: any = {};
      let current: any = deepObj;
      for (let i = 0; i < 10000; i++) {
        current.nested = {};
        current = current.nested;
      }

      // Should throw a controlled typed error now (fail-closed policy)
      expect(() => toCanonicalValue(deepObj)).toThrow(InvalidParameterError);
    });

    it("should reject extremely large payloads", () => {
      const largePayload = "x".repeat(10 * 1024 * 1024 + 1); // >10MB

      expect(() => safeStableStringify(largePayload)).toThrow(InvalidParameterError);
    });

    it("should handle mixed data types in arrays", () => {
      const mixed = [
        "string",
        42,
        true,
        null,
        undefined,
        { nested: "object" },
        [1, 2, 3],
      ];

      const canonical = toCanonicalValue(mixed);

      expect(canonical).toEqual([
        "string",
        42,
        true,
        null,
        undefined,
        { nested: "object" },
        [1, 2, 3],
      ]);
    });
  });

  describe("PostMessage Sanitization", () => {
    it("should convert to null prototype objects", () => {

      const payload = { a: 1, __proto__: { polluted: true } };

      const sanitized = __test_toNullProto(payload);

      expect(sanitized).toEqual({ a: 1 });
      expect(Object.getPrototypeOf(sanitized)).toBe(null);
      expect((sanitized as any).polluted).toBeUndefined();
    });

    it("should handle nested prototype pollution", () => {

      const payload = {
        data: {
          __proto__: {
            constructor: {
              prototype: {
                polluted: true,
              },
            },
          },
        },
      };

      const sanitized = __test_toNullProto(payload);

      expect(sanitized).toEqual({ data: {} });
      expect((sanitized as any).data.polluted).toBeUndefined();
    });
  });
});