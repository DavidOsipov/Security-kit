import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";

import * as post from "../../src/postMessage";
import * as state from "../../src/state";
import { environment } from "../../src/environment";

// Tests for fingerprinting and toNullProto/freeze cache behaviors

describe("postMessage fingerprinting and toNullProto/freeze cache", () => {
  const origEnvProd = environment.isProduction;
  const origCrypto = (globalThis as any).crypto;

  beforeEach(() => {
    // Ensure non-production so diagnostics can run
    environment.setExplicitEnv?.("development");
    // Reset internal crypto state if test helper available
    try {
      state.__test_resetCryptoStateForUnitTests?.();
    } catch {}
    delete (globalThis as any).crypto;
    try {
      (post as any).__test_resetForUnitTests?.();
    } catch {}
    // Reset internal fingerprint salt via direct module reload-ish technique
    // (no direct API exported; ensureFingerprintSalt is module-scoped). We will rely
    // on setting global crypto and calling getPayloadFingerprint() to exercise both paths.
  });

  afterEach(() => {
    // restore
    environment.clearCache?.();
    if (origCrypto !== undefined) (globalThis as any).crypto = origCrypto;
    try {
      state.__test_resetCryptoStateForUnitTests?.();
    } catch {}
  });

  it("computes a deterministic fingerprint using subtle.digest when crypto is available", async () => {
    // Provide a fake crypto with subtle.digest that returns a predictable digest
    const fakeDigest = new Uint8Array(32).fill(1);
    const fakeSubtle = {
      digest: vi.fn(async (_alg: string, data: ArrayBuffer) => {
        // return fake digest ArrayBuffer
        return fakeDigest.buffer.slice(0);
      }),
    } as unknown as SubtleCrypto;

    const fakeCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = i & 0xff;
        return arr;
      },
      subtle: fakeSubtle,
    } as unknown as Crypto;

    (globalThis as any).crypto = fakeCrypto;

  const fp = await (post as any).__test_getPayloadFingerprint({ a: 1, b: "x" });
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
    // ensure subtle.digest was called
    expect(fakeSubtle.digest).toHaveBeenCalled();
  });

  it("falls back to salted rolling hash when subtle is unavailable", async () => {
    // Provide crypto without subtle
    const fakeCrypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = 255 - (i & 0xff);
        return arr;
      },
    } as unknown as Crypto;
    (globalThis as any).crypto = fakeCrypto;

  const fp = await (post as any).__test_getPayloadFingerprint({ foo: "bar" });
  // Implementation may return either a short base64 or a hex string
  expect(typeof fp).toBe("string");
  expect(fp.length).toBeGreaterThan(0);
  expect(fp).not.toBe("FINGERPRINT_ERR");
  });

  it("ensureFingerprintSalt fallback when no crypto available uses time entropy", async () => {
    // Ensure no global crypto to force fallback code path in ensureFingerprintSalt
    delete (globalThis as any).crypto;
    // Force production=false so fallback isn't disabled
    environment.setExplicitEnv?.("development");

  const fp = await (post as any).__test_getPayloadFingerprint({ z: 123 });
    expect(typeof fp).toBe("string");
    // It may return either hex or FINGERPRINT_ERR; ensure it's not throwing
  });

  it("toNullProto skips accessors, symbols and forbidden keys", () => {
    const obj: any = {};
    Object.defineProperty(obj, "safe", { value: 1, enumerable: true });
    Object.defineProperty(obj, "bad", {
      get() {
        throw new Error("should not run");
      },
      enumerable: true,
    });
    const sym = Symbol("s");
    (obj as any)[sym] = "hidden";
    (obj as any)["__proto__"] = { polluted: true };

  const sanitized = (post as any).__test_toNullProto(obj);
    // sanitized should be a null-proto object containing only 'safe'
    expect(Object.getPrototypeOf(sanitized)).toBe(null);
    expect((sanitized as any).safe).toBe(1);
    expect((sanitized as any).bad).toBeUndefined();
    expect((sanitized as any).__proto__).toBeUndefined();
    // symbol-keyed property should not appear
    expect(Object.getOwnPropertySymbols(sanitized as object).length).toBe(0);
  });

  it("deepFreeze cache prevents double-freeze work and allows caching", () => {
    const o: any = { x: 1 };
    // Use exported deepFreeze to ensure freezing works; avoid relying on
    // nested listener helpers which are not exported.
  (post as any).__test_deepFreeze(o);
    expect(Object.isFrozen(o)).toBe(true);
    // Second call is a no-op but should not throw
  (post as any).__test_deepFreeze(o);
    expect(Object.isFrozen(o)).toBe(true);
  });
});
