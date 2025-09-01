import { describe, it, expect, vi, beforeEach } from "vitest";

// Set up test environment flag to enable test APIs
process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

// Mock the config module
vi.mock("../../src/config", () => ({
  getHandshakeConfig: vi.fn(() => ({
    allowedNonceFormats: ["base64", "base64url", "hex"],
    handshakeMaxNonceLength: 100,
  })),
  setHandshakeConfig: vi.fn(),
}));

// Mock encoding utilities
vi.mock("../../src/encoding-utils", () => ({
  isLikelyBase64: vi.fn((str: string) => str.length > 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(str)),
  isLikelyBase64Url: vi.fn((str: string) => str.length > 0 && /^[A-Za-z0-9_-]*$/.test(str)),
}));

// Import the worker module to test its functions
import * as workerModule from "../../src/worker/signing-worker";

describe("signing-worker unit tests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("__test_validateHandshakeNonce", () => {
    it("should validate base64 nonce correctly", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate).toBeDefined();
      expect(validate!("SGVsbG8gV29ybGQ=")).toBe(true); // "Hello World" in base64
    });

    it("should validate base64url nonce correctly", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate!("SGVsbG8gV29ybGQ")).toBe(true); // "Hello World" in base64url
    });

    it("should validate hex nonce correctly", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate!("48656c6c6f20576f726c64")).toBe(true); // "Hello World" in hex
    });

    it("should reject invalid base64", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate!("invalid@base64!")).toBe(false);
    });

    it("should reject non-string input", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate!(123 as any)).toBe(false);
      expect(validate!(null as any)).toBe(false);
      expect(validate!(undefined as any)).toBe(false);
    });

    it("should reject empty string", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      expect(validate!("")).toBe(false);
    });

    it("should reject nonce exceeding max length", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      const longNonce = "a".repeat(101);
      expect(validate!(longNonce)).toBe(false);
    });
  });

  describe("worker module exports", () => {
    it("should export the test helper function", () => {
      expect(workerModule.__test_validateHandshakeNonce).toBeDefined();
    });

    it("should be able to import the worker module", () => {
      expect(workerModule).toBeDefined();
    });
  });

  describe("comprehensive validation testing", () => {
    it("should test multiple validation scenarios to increase coverage", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      
      // Test various scenarios to exercise different code paths
      expect(validate!("SGVsbG8gV29ybGQ=")).toBe(true); // base64
      expect(validate!("SGVsbG8gV29ybGQ")).toBe(true);  // base64url
      expect(validate!("48656c6c6f20576f726c64")).toBe(true); // hex
      expect(validate!("")).toBe(false); // empty
      expect(validate!("invalid@chars!")).toBe(false); // invalid
      expect(validate!("a".repeat(101))).toBe(false); // too long
    });

    it("should handle edge cases in validation", () => {
      const validate = workerModule.__test_validateHandshakeNonce;
      
      // Test edge cases
      expect(validate!("A")).toBe(true); // minimal valid
      expect(validate!("1")).toBe(true); // hex digit
      expect(validate!("/=")).toBe(true); // base64 padding
      expect(validate!("_")).toBe(true); // base64url char
      expect(validate!("-")).toBe(true); // base64url char
    });
  });
});