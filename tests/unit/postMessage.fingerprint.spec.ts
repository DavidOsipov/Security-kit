import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { CryptoUnavailableError } from "../../src/errors";

describe("postMessage fingerprinting (subtle and fallback)", () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });
  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    vi.restoreAllMocks();
  });

  it("getPayloadFingerprint uses subtle.digest when available", async () => {
    // Use dynamic imports for clean module isolation
    const postMessage = await import("../../src/postMessage");
    const state = await import("../../src/state");

    // Fake crypto with subtle.digest that returns a deterministic ArrayBuffer
    const fakeDigest = async (_alg: string, _buf: ArrayBuffer) => {
      // return 32-byte zero buffer
      return new Uint8Array(32).buffer;
    };
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: { digest: fakeDigest },
    } as unknown as Crypto;

    vi.spyOn(state, "ensureCrypto").mockResolvedValue(fakeCrypto);

    const fp = await postMessage.__test_getPayloadFingerprint({ a: 1 });
    expect(typeof fp).toBe("string");
    expect(fp.length).toBeGreaterThan(0);
  });

  it("ensureFingerprintSalt fallback when ensureCrypto rejects", async () => {
    // Use dynamic imports for clean module isolation
    const postMessage = await import("../../src/postMessage");
    const state = await import("../../src/state");

    const spy = vi
      .spyOn(state, "ensureCrypto")
      .mockRejectedValue(new CryptoUnavailableError());
    // calling ensureFingerprintSalt should not throw in dev and should produce a Uint8Array
    const salt = await postMessage.__test_ensureFingerprintSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBeGreaterThan(0);
    spy.mockRestore();
  });
});
