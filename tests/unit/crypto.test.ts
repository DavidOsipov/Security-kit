import { describe, it, expect } from "vitest";
import {
  generateSecureIdSync,
  generateSecureStringSync,
  getSecureRandomInt,
  generateSRI,
  createAesGcmNonce,
} from "../../src/crypto";
import { InvalidParameterError } from "../../src/errors";

describe("crypto module (unit)", () => {
  it("generateSecureIdSync produces hex string of requested length", () => {
    const s = generateSecureIdSync(16);
    expect(typeof s).toBe("string");
    expect(s.length).toBe(16);
    // hex only
    expect(/^[0-9a-f]+$/.test(s)).toBe(true);
  });

  it("generateSecureStringSync respects single-char alphabet", () => {
    const out = generateSecureStringSync("x", 10);
    expect(out).toBe("x".repeat(10));
  });

  it("generateSecureStringSync throws for invalid alphabet", () => {
    expect(() => generateSecureStringSync("", 4)).toThrow(
      InvalidParameterError,
    );
    expect(() => generateSecureStringSync("aa", 4)).toThrow(
      InvalidParameterError,
    );
  });

  it("getSecureRandomInt handles min===max and invalid ranges", async () => {
    expect(await getSecureRandomInt(5, 5)).toBe(5);
    await expect(getSecureRandomInt(10, 1)).rejects.toBeInstanceOf(
      InvalidParameterError,
    );
  });

  it("generateSRI accepts string input and returns expected prefix", async () => {
    const s = await generateSRI("hello", "sha256");
    expect(s.startsWith("sha256-")).toBe(true);
  });

  it("createAesGcmNonce enforces length bounds", () => {
    const n = createAesGcmNonce(12);
    expect(n.byteLength).toBe(12);
  });
});
