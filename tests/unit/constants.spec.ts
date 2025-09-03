import { describe, it, expect } from "vitest";
import {
  isForbiddenKey,
  getForbiddenKeys,
  DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH,
  NONCE_FORMAT_BASE64,
  NONCE_FORMAT_BASE64URL,
  NONCE_FORMAT_HEX,
  DEFAULT_NONCE_FORMATS,
  type NonceFormat,
} from "../../src/constants.js";

describe("constants", () => {
  describe("isForbiddenKey", () => {
    it("returns true for forbidden keys", () => {
      expect(isForbiddenKey("__proto__")).toBe(true);
      expect(isForbiddenKey("prototype")).toBe(true);
      expect(isForbiddenKey("constructor")).toBe(true);
    });

    it("returns false for non-forbidden keys", () => {
      expect(isForbiddenKey("normalKey")).toBe(false);
      expect(isForbiddenKey("anotherKey")).toBe(false);
      expect(isForbiddenKey("")).toBe(false);
    });

    it("is case sensitive", () => {
      expect(isForbiddenKey("__PROTO__")).toBe(false);
      expect(isForbiddenKey("Prototype")).toBe(false);
      expect(isForbiddenKey("CONSTRUCTOR")).toBe(false);
    });
  });

  describe("getForbiddenKeys", () => {
    it("returns a readonly array of forbidden keys", () => {
      const keys = getForbiddenKeys();
      expect(Array.isArray(keys)).toBe(true);
      expect(keys).toContain("__proto__");
      expect(keys).toContain("prototype");
      expect(keys).toContain("constructor");
      expect(keys).toHaveLength(3);
    });

    it("returns a copy that is separate from the original", () => {
      const keys = getForbiddenKeys();
      expect(Array.isArray(keys)).toBe(true);
      expect(keys).toContain("__proto__");
      expect(keys).toContain("prototype");
      expect(keys).toContain("constructor");
      expect(keys).toHaveLength(3);
    });
  });

  describe("handshake constants", () => {
    it("has correct default handshake max nonce length", () => {
      expect(DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH).toBe(1024);
      expect(typeof DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH).toBe("number");
    });
  });

  describe("nonce format constants", () => {
    it("has correct nonce format constants", () => {
      expect(NONCE_FORMAT_BASE64).toBe("base64");
      expect(NONCE_FORMAT_BASE64URL).toBe("base64url");
      expect(NONCE_FORMAT_HEX).toBe("hex");
    });

    it("has correct default nonce formats array", () => {
      expect(DEFAULT_NONCE_FORMATS).toEqual(["base64", "base64url"]);
      expect(DEFAULT_NONCE_FORMATS).toHaveLength(2);
      expect(DEFAULT_NONCE_FORMATS).toContain("base64");
      expect(DEFAULT_NONCE_FORMATS).toContain("base64url");
    });

    it("nonce format type is correctly defined", () => {
      const format: NonceFormat = "base64";
      expect(format).toBe("base64");

      const format2: NonceFormat = "base64url";
      expect(format2).toBe("base64url");

      const format3: NonceFormat = "hex";
      expect(format3).toBe("hex");
    });
  });
});