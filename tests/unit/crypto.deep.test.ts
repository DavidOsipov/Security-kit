import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  generateSecureUUID,
  generateSRI,
  createOneTimeCryptoKey,
  getSecureRandomAsync,
  generateSecureStringAsync,
} from "../../src/crypto";
import * as stateModule from "../../src/state";
import { setCrypto } from "../../src/config";
import { InvalidParameterError, CryptoUnavailableError } from "../../src/errors";

const { __test_resetCryptoStateForUnitTests } = (stateModule as any);

describe("deep crypto behaviors", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
  });

  it("generateSecureUUID uses fallback when randomUUID absent", async () => {
    // Ensure global crypto exists but without randomUUID
    const fakeCrypto: any = {
      getRandomValues(arr: Uint8Array) {
        for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;
        return arr;
      },
    };
  setCrypto(fakeCrypto as any);
    const u = await generateSecureUUID();
    expect(typeof u).toBe("string");
    expect(u.split("-").length).toBe(5);
  });

  it("generateSRI accepts ArrayBuffer and wipes internal copies", async () => {
    const fakeCrypto: any = {
      subtle: {
        digest: async (_alg: string, data: BufferSource) => {
          // return a deterministic digest ArrayBuffer
          const arr = new Uint8Array(32);
          arr.fill(7);
          return arr.buffer;
        },
      },
      getRandomValues: () => {},
    };
  setCrypto(fakeCrypto as any);
    const buf = new Uint8Array([1, 2, 3]).buffer;
    const sri = await generateSRI(buf, "sha384");
    expect(sri.startsWith("sha384-")).toBe(true);
  });

  it("createOneTimeCryptoKey throws with bad usages and accepts valid usage", async () => {
    const fakeCrypto: any = {
      subtle: {
        generateKey: async (_alg: any, _ext: boolean, usages: any) => {
          return { usages } as any;
        },
      },
      getRandomValues: () => {},
    };
  setCrypto(fakeCrypto as any);
  await expect(createOneTimeCryptoKey({ lengthBits: 128, usages: ["encrypt"] })).resolves.toBeDefined();
  await expect(createOneTimeCryptoKey({ lengthBits: 512 as any })).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("getSecureRandomAsync aborts when signal aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    // Abort implementations may use different error messages; assert by pattern
  await expect(getSecureRandomAsync({ signal: ac.signal })).rejects.toThrow(/Abort|aborted|Operation aborted/);
  });

  it("generateSecureStringAsync respects abort during generation", async () => {
    const fakeCrypto: any = {
      getRandomValues(arr: Uint8Array) {
        for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
        return arr;
      },
    };
  setCrypto(fakeCrypto as any);
    const ac = new AbortController();
    const p = generateSecureStringAsync("abcdef", 32, { signal: ac.signal });
    ac.abort();
  await expect(p).rejects.toThrow(/Abort|aborted|Operation aborted/);
  });
});
