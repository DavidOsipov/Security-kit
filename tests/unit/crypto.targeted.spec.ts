import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

function makeFakeCrypto(opts?: { withRandomUUID?: boolean; subtle?: any }) {
  const fake: any = {
    getRandomValues(buf: Uint8Array | Uint32Array | BigUint64Array) {
      // deterministic but varied bytes
      for (let i = 0; i < (buf as any).length; i++) {
        if (
          typeof BigUint64Array !== "undefined" &&
          buf instanceof BigUint64Array
        ) {
          // BigUint64Array expects BigInt values
          (buf as BigUint64Array)[i] = BigInt((i * 13) & 0xff);
        } else {
          (buf as any)[i] = (i * 13) & 0xff;
        }
      }
      return buf;
    },
  };
  if (opts && opts.withRandomUUID)
    fake.randomUUID = () => "11111111-2222-3333-4444-555555555555";
  if (opts && opts.subtle !== undefined) fake.subtle = opts.subtle;
  return fake as Crypto;
}

describe("crypto - targeted branches", () => {
  let state: any;
  let cryptoModule: any;

  beforeEach(async () => {
    vi.resetModules();
    state = await import("../../src/state");
    if ((state as any).__test_resetCryptoStateForUnitTests)
      (state as any).__test_resetCryptoStateForUnitTests();
    cryptoModule = undefined;
  });

  afterEach(async () => {
    if (state && (state as any).__test_resetCryptoStateForUnitTests)
      (state as any).__test_resetCryptoStateForUnitTests();
  });

  it("generateSecureUUID uses crypto.randomUUID when present", async () => {
    const fake = makeFakeCrypto({ withRandomUUID: true });
    (state as any)._setCrypto(fake);
    cryptoModule = await import("../../src/crypto");
    const id = await cryptoModule.generateSecureUUID();
    expect(id).toBe("11111111-2222-3333-4444-555555555555");
  });

  it("createOneTimeCryptoKey falls back to importKey when subtle.generateKey missing", async () => {
    // subtle without generateKey should exercise importKey path
    const subtleMock = {
      importKey: async (
        _format: any,
        _data: ArrayBuffer,
        _alg: any,
        _ext: boolean,
        _usages: any,
      ) => {
        return { kty: "sym" } as unknown as CryptoKey;
      },
    };
    const fake = makeFakeCrypto({ subtle: subtleMock });
    (state as any)._setCrypto(fake);
    cryptoModule = await import("../../src/crypto");
    const key = await cryptoModule.createOneTimeCryptoKey({ lengthBits: 128 });
    expect(key).toBeDefined();
  });

  it("getSecureRandomInt exercises BigUint64Array path when range > 32-bit", async () => {
    // Provide a fake with BigUint64Array available by virtue of environment
    const fake = makeFakeCrypto();
    (state as any)._setCrypto(fake);
    cryptoModule = await import("../../src/crypto");
    // Use the allowed numeric bounds to produce a range > 0x100000000
    // (min = -2^31, max = 2^31) -> rangeBig = 2^32 + 1
    const v = await cryptoModule.getSecureRandomInt(-2147483648, 2147483648);
    expect(typeof v).toBe("number");
    // result should be within the requested bounds
    expect(v).toBeGreaterThanOrEqual(-2147483648);
    expect(v).toBeLessThanOrEqual(2147483648);
  });

  it("generateSRI supports sha256/sha512 algorithms and validates input", async () => {
    const digestMap: Record<string, ArrayBuffer> = {
      "SHA-256": new Uint8Array([9, 8, 7]).buffer,
      "SHA-384": new Uint8Array([1, 2, 3]).buffer,
      "SHA-512": new Uint8Array([4, 5, 6]).buffer,
    };
    const subtleMock = {
      digest: async (alg: string, _data: any) => {
        return digestMap[alg] || digestMap["SHA-384"];
      },
    };
    const fake = makeFakeCrypto({ subtle: subtleMock });
    (state as any)._setCrypto(fake);
    cryptoModule = await import("../../src/crypto");
    const { InvalidParameterError } = await import("../../src/errors");
    await expect(cryptoModule.generateSRI(null as any)).rejects.toThrow(
      InvalidParameterError,
    );
    const s256 = await cryptoModule.generateSRI("ok", "sha256");
    expect(s256.startsWith("sha256-")).toBe(true);
    const s512 = await cryptoModule.generateSRI(
      new Uint8Array([1, 2, 3]).buffer,
      "sha512",
    );
    expect(s512.startsWith("sha512-")).toBe(true);
  });

  it("generateSecureStringSync rejects inefficient alphabet sizes", async () => {
    cryptoModule = await import("../../src/crypto");
    // alphabet length that triggers acceptanceRatio check (small len against mask)
    expect(() => cryptoModule.generateSecureStringSync("ab", 10000)).toThrow();
  });

  it("createAesGcmNonce returns correct length for allowed sizes", async () => {
    cryptoModule = await import("../../src/crypto");
    const n12 = cryptoModule.createAesGcmNonce(12);
    expect(n12.length).toBe(12);
    const n16 = cryptoModule.createAesGcmNonce(16);
    expect(n16.length).toBe(16);
  });
});
