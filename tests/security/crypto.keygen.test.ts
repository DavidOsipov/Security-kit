// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect, vi, afterEach } from "vitest";
import { createOneTimeCryptoKey } from "../../src/crypto";
import { __resetCryptoStateForTests } from "../../src/state";

// These tests validate that we prefer non-extractable generateKey when available
// and only fall back to importKey when generateKey is unavailable. No raw key
// material should be observable by userland when generateKey is present.

describe("createOneTimeCryptoKey", () => {
  afterEach(() => {
    // Restore any globals we stubbed
    vi.unstubAllGlobals();
    // Reset cached crypto provider between tests
    __resetCryptoStateForTests();
  });

  it("uses subtle.generateKey when available (non-extractable)", async () => {
    const calls: { generateKey: number; importKey: number } = {
      generateKey: 0,
      importKey: 0,
    };
    const fakeKey = {} as unknown as CryptoKey;
    const fakeSubtle: Partial<SubtleCrypto> = {
      async generateKey() {
        calls.generateKey++;
        return fakeKey as any;
      },
      async importKey() {
        calls.importKey++;
        throw new Error("should not be called when generateKey exists");
      },
    };
    vi.stubGlobal(
      "crypto",
      {
        getRandomValues<T extends ArrayBufferView>(arr: T) {
          return arr;
        },
        subtle: fakeSubtle as SubtleCrypto,
      } as unknown as Crypto,
    );

    const key = await createOneTimeCryptoKey({
      lengthBits: 256,
      usages: ["encrypt", "decrypt"],
    });
    expect(key).toBe(fakeKey);
    expect(calls.generateKey).toBe(1);
    expect(calls.importKey).toBe(0);
  });

  it("falls back to importKey only when generateKey is unavailable", async () => {
    const calls: { generateKey: number; importKey: number } = {
      generateKey: 0,
      importKey: 0,
    };
    const fakeKey = {} as unknown as CryptoKey;
    const fakeSubtle: Partial<SubtleCrypto> = {
      // simulate absence of generateKey
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      generateKey: undefined as any,
      async importKey() {
        calls.importKey++;
        return fakeKey;
      },
    };
    vi.stubGlobal(
      "crypto",
      {
        getRandomValues<T extends ArrayBufferView>(arr: T) {
          return arr;
        },
        subtle: fakeSubtle as SubtleCrypto,
      } as unknown as Crypto,
    );

    const key = await createOneTimeCryptoKey({ lengthBits: 128, usages: ["encrypt"] });
    expect(key).toBe(fakeKey);
    expect(calls.generateKey).toBe(0);
    expect(calls.importKey).toBe(1);
  });
});
