import { describe, it, expect, vi } from "vitest";
import * as SK from "../../src";

const { secureCompare, secureCompareAsync, setCrypto, InvalidParameterError } =
  SK as any;

describe("string comparison helpers", () => {
  it("secureCompare normalizes NFC and compares", () => {
    const a = "e\u0301";
    const b = "\u00E9";
    expect(secureCompare(a, b)).toBe(true);
    expect(secureCompare("abc", "abd")).toBe(false);
    const long = "x".repeat(4097);
    expect(() => secureCompare(long, "x")).toThrow(InvalidParameterError);
  });

  it("secureCompareAsync uses digest path and falls back safely", async () => {
    await expect(secureCompareAsync("same", "same")).resolves.toBe(true);
    await expect(secureCompareAsync("a", "b")).resolves.toBe(false);

    const stub = {
      getRandomValues: (a: any) => (a.fill?.(1), a),
      subtle: {},
    } as unknown as Crypto;
    setCrypto(stub);
    await expect(secureCompareAsync("x", "x")).resolves.toBe(true);
    await expect(secureCompareAsync("x", "y")).resolves.toBe(false);
    setCrypto(null);

    const long = "x".repeat(4097);
    await expect(secureCompareAsync(long, "x")).rejects.toBeInstanceOf(
      InvalidParameterError,
    );
  });
});
