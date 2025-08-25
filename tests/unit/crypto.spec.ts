import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import * as cryptoModule from "../../src/crypto";
import * as state from "../../src/state";
import * as utils from "../../src/utils";
import { CryptoUnavailableError, InvalidParameterError, RandomGenerationError } from "../../src/errors";

describe("crypto.ts - core primitives", () => {
  beforeEach(() => {
    // Ensure test isolation: reset any test-only state util if available
    if (typeof state.__test_resetCryptoStateForUnitTests === "function") {
      state.__test_resetCryptoStateForUnitTests();
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("getSecureRandomBytesSync returns correct length and type", () => {
    const arr = cryptoModule.getSecureRandomBytesSync(16);
    expect(arr).toBeInstanceOf(Uint8Array);
    expect(arr.length).toBe(16);
  });

  it("getSecureRandomAsync throws on aborted signal", async () => {
    await expect(
      cryptoModule.getSecureRandomAsync({ signal: { aborted: true } as AbortSignal }),
    ).rejects.toBeTruthy();
  });

  it("getSecureRandom returns number in [0,1)", () => {
    const v = cryptoModule.getSecureRandom();
    expect(typeof v).toBe("number");
    expect(v).toBeGreaterThanOrEqual(0);
    expect(v).toBeLessThan(1);
  });

  it("getSecureRandomInt validates params and handles min===max", async () => {
    await expect(cryptoModule.getSecureRandomInt(5, 4)).rejects.toBeInstanceOf(InvalidParameterError);
    const same = await cryptoModule.getSecureRandomInt(7, 7);
    expect(same).toBe(7);
  });

  it("getSecureRandomInt respects abort signal immediately", async () => {
    await expect(
      cryptoModule.getSecureRandomInt(0, 10, { signal: { aborted: true } as AbortSignal }),
    ).rejects.toBeTruthy();
  });

  it("shouldExecuteThrottled validates probability and returns boolean", async () => {
    expect(() => cryptoModule.shouldExecuteThrottled(-1 as unknown as number)).toThrow(InvalidParameterError);
    expect(() => cryptoModule.shouldExecuteThrottled(0.5)).not.toThrow();
    const r = cryptoModule.shouldExecuteThrottled(0.5);
    expect(typeof r).toBe("boolean");
    const rAsync = await cryptoModule.shouldExecuteThrottledAsync(0.1);
    expect(typeof rAsync).toBe("boolean");
  });

  it("generateSecureStringSync handles single-character alphabet and rejects bad alphabets", () => {
    expect(cryptoModule.generateSecureStringSync("x", 5)).toBe("xxxxx");
    expect(() => cryptoModule.generateSecureStringSync("", 4)).toThrow(InvalidParameterError);
    expect(() => cryptoModule.generateSecureStringSync("aa", 4)).toThrow(InvalidParameterError);
  });

  it("generateSecureStringAsync produces expected length and respects abort", async () => {
    const s = await cryptoModule.generateSecureStringAsync("abcd", 10);
    expect(typeof s).toBe("string");
    expect(s.length).toBe(10);
    await expect(
      cryptoModule.generateSecureStringAsync("abcd", 10, { signal: { aborted: true } as AbortSignal }),
    ).rejects.toBeTruthy();
  });

  it("generateSecureId/Sync produce hex strings of requested length", async () => {
    const a = cryptoModule.generateSecureIdSync(32);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    const b = await cryptoModule.generateSecureId(16);
    expect(b).toMatch(/^[0-9a-f]{16}$/);
  });

  it("generateSecureUUID returns a valid UUID v4-like string", async () => {
    const uuid = await cryptoModule.generateSecureUUID();
    expect(typeof uuid).toBe("string");
    const parts = uuid.split("-");
    expect(parts.length).toBe(5);
    expect(parts[0].length).toBe(8);
    expect(parts[2].length).toBe(4);
    expect(parts[3].length).toBe(4);
  });

  it("createOneTimeCryptoKey validates length arguments and usages", async () => {
    await expect(
      cryptoModule.createOneTimeCryptoKey({ lengthBits: 128, length: 128 } as unknown as any),
    ).rejects.toBeInstanceOf(InvalidParameterError);
    await expect(cryptoModule.createOneTimeCryptoKey({ lengthBits: 128, usages: ["encrypt"] })).resolves.toBeDefined();
    await expect(cryptoModule.createOneTimeCryptoKey({ lengthBits: 256, usages: ["encrypt", "decrypt"] })).resolves.toBeDefined();
    await expect(cryptoModule.createOneTimeCryptoKey({ lengthBits: 42 as any })).rejects.toBeInstanceOf(InvalidParameterError);
    await expect(cryptoModule.createOneTimeCryptoKey({ usages: [] as any })).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("createAesGcmNonce validates byteLength and returns correct size", () => {
    const n = cryptoModule.createAesGcmNonce();
    expect(n).toBeInstanceOf(Uint8Array);
    expect(n.length).toBe(12);
    expect(() => cryptoModule.createAesGcmNonce(11)).toThrow(InvalidParameterError);
  });

  it("generateSRI works for string and ArrayBuffer inputs and validates algorithm", async () => {
    const s = await cryptoModule.generateSRI("hello", "sha256");
    expect(s).toMatch(/^sha256-[A-Za-z0-9+/=]+$/);
    const buf = new TextEncoder().encode("world").buffer;
    const s2 = await cryptoModule.generateSRI(buf, "sha384");
    expect(s2).toMatch(/^sha384-[A-Za-z0-9+/=]+$/);
    await expect(cryptoModule.generateSRI(null as unknown as any)).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("secureCompare and secureCompareAsync behave correctly and error on too-long inputs", async () => {
  expect(utils.secureCompare("a", "a")).toBe(true);
  expect(utils.secureCompare("a", "b")).toBe(false);
    const long = "x".repeat(5000);
    expect(() => utils.secureCompare(long, long)).toThrow(InvalidParameterError);

    // secureCompareAsync: when SubtleCrypto is unavailable and requireCrypto=true -> throw
    const ensureCryptoSpy = vi.spyOn(state, "ensureCrypto").mockResolvedValue({} as unknown as Crypto);
    await expect(utils.secureCompareAsync("a", "a", { requireCrypto: true })).rejects.toBeInstanceOf(CryptoUnavailableError);
    ensureCryptoSpy.mockRestore();

    // fallback path should return same result as sync
    const r = await utils.secureCompareAsync("abc", "abc");
    expect(r).toBe(true);
  });
});
