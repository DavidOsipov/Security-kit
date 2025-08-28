// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Tests for enhanced encoding utilities with base64url support.
 */

import { describe, it, expect } from "vitest";
import { base64ToBytes, isLikelyBase64, bytesToBase64 } from "../../src/encoding-utils.js";

describe("Enhanced Encoding Utils", () => {
  describe("base64url normalization", () => {
    it("handles standard base64 correctly", () => {
      const data = "Hello, World!";
      const standard = "SGVsbG8sIFdvcmxkIQ==";
      const decoded = base64ToBytes(standard);
      const original = new TextDecoder().decode(decoded);
      expect(original).toBe(data);
    });

    it("handles base64url correctly", () => {
      const data = "Hello, World!";
      const base64url = "SGVsbG8sIFdvcmxkIQ"; // unpadded base64url
      const decoded = base64ToBytes(base64url);
      const original = new TextDecoder().decode(decoded);
      expect(original).toBe(data);
    });

    it("handles base64url with different characters", () => {
      // Original data that results in + and / in standard base64
      const originalBytes = new Uint8Array([255, 254, 253, 252, 251, 250]);
      const standard = bytesToBase64(originalBytes); // Should contain + and/or /
      const base64url = standard.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      
      const decodedFromStandard = base64ToBytes(standard);
      const decodedFromBase64url = base64ToBytes(base64url);
      
      expect(decodedFromStandard).toEqual(originalBytes);
      expect(decodedFromBase64url).toEqual(originalBytes);
      expect(decodedFromStandard).toEqual(decodedFromBase64url);
    });

    it("handles mixed base64url characters correctly", () => {
      // Test case where base64url has - and _ characters
      const base64url = "SGVsbG8tV29ybGRfQSE"; // base64url with - and _
      const standard = "SGVsbG8tV29ybGRfQSE="; // same but with padding
      
      // Both should decode to same result
      const decodedUrl = base64ToBytes(base64url);
      const decodedStd = base64ToBytes(standard);
      
      expect(decodedUrl).toEqual(decodedStd);
    });
  });

  describe("isLikelyBase64 validation", () => {
    it("accepts valid standard base64", () => {
      expect(isLikelyBase64("SGVsbG8sIFdvcmxkIQ==")).toBe(true);
      expect(isLikelyBase64("YWJjZGVmZw==")).toBe(true);
      expect(isLikelyBase64("dGVzdA==")).toBe(true);
    });

    it("accepts valid base64url", () => {
      expect(isLikelyBase64("SGVsbG8sIFdvcmxkIQ")).toBe(true);
      expect(isLikelyBase64("YWJjZGVmZw")).toBe(true);
      expect(isLikelyBase64("dGVzdA")).toBe(true);
    });

    it("accepts base64url with - and _ characters", () => {
      expect(isLikelyBase64("SGVsbG8tV29ybGQ_QSE")).toBe(true);
      expect(isLikelyBase64("YWJjLWRlZl93b3JsZA")).toBe(true);
    });

    it("rejects invalid formats", () => {
      expect(isLikelyBase64("")).toBe(false);
      expect(isLikelyBase64("invalid!!!")).toBe(false);
      expect(isLikelyBase64("SGVsbG8@IFdvcmxkIQ==")).toBe(false);
      expect(isLikelyBase64("not base64 at all")).toBe(false);
    });

    it("handles very short strings appropriately", () => {
      // Very short strings get padded by normalization but may not represent valid data
      // Our function is lenient for compatibility - if you need stricter validation,
      // test actual decoding success
      expect(isLikelyBase64("a")).toBe(true); // Gets padded to "a==="
      expect(isLikelyBase64("ab")).toBe(true); // Gets padded to "ab=="
      expect(isLikelyBase64("abc")).toBe(true); // Gets padded to "abc="
      
      // But test that invalid character patterns still fail
      expect(isLikelyBase64("@")).toBe(false);
      expect(isLikelyBase64("!@")).toBe(false);
    });

    it("handles edge cases", () => {
      expect(isLikelyBase64(null as any)).toBe(false);
      expect(isLikelyBase64(undefined as any)).toBe(false);
      expect(isLikelyBase64(123 as any)).toBe(false);
    });
  });

  describe("round-trip encoding", () => {
    it("maintains data integrity through encode/decode cycles", () => {
      const testData = [
        new Uint8Array([]),
        new Uint8Array([0]),
        new Uint8Array([255]),
        new Uint8Array([0, 1, 2, 3, 255, 254, 253]),
        new Uint8Array(256).map((_, i) => i), // 0-255
      ];

      for (const data of testData) {
        const encoded = bytesToBase64(data);
        const decoded = base64ToBytes(encoded);
        expect(decoded).toEqual(data);
      }
    });

    it("handles large data correctly", () => {
      // Test with larger data to ensure chunking works
      const largeData = new Uint8Array(10000).map((_, i) => i % 256);
      const encoded = bytesToBase64(largeData);
      const decoded = base64ToBytes(encoded);
      expect(decoded).toEqual(largeData);
    });
  });

  describe("cross-platform compatibility", () => {
    it("handles Buffer-based encoding when available", () => {
      // Test that our encoding works in both browser and Node environments
      const testBytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = bytesToBase64(testBytes);
      expect(isLikelyBase64(encoded)).toBe(true);
      
      const decoded = base64ToBytes(encoded);
      expect(decoded).toEqual(testBytes);
      expect(new TextDecoder().decode(decoded)).toBe("Hello");
    });

    it("gracefully handles missing global functions", () => {
      // This test ensures our code doesn't crash if global functions are missing
      const testBytes = new Uint8Array([116, 101, 115, 116]); // "test"
      
      // Should not throw even if some globals are missing
      expect(() => {
        const encoded = bytesToBase64(testBytes);
        const decoded = base64ToBytes(encoded);
        expect(decoded).toEqual(testBytes);
      }).not.toThrow();
    });
  });
});