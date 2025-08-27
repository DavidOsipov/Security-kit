import { describe, it, expect, vi } from "vitest";

describe("postMessage stable fingerprinting", () => {
  it("produces identical fingerprints for objects with different key insertion orders", async () => {
    vi.resetModules();
    const state = await import("../../src/state");
    const fakeSubtle = { digest: async (b: ArrayBuffer) => new Uint8Array([1, 2, 3, 4]).buffer };
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
        return buf;
      },
      subtle: fakeSubtle,
    } as any;
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => fakeCrypto as any);

    const postMessage = await import("../../src/postMessage");
    // allow test internals via global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

    const a = { a: 1, b: { c: 2 } };
    const b = { b: { c: 2 }, a: 1 };

    const fp1 = await postMessage.__test_getPayloadFingerprint(a);
    const fp2 = await postMessage.__test_getPayloadFingerprint(b);
    expect(fp1).toBe(fp2);
  });
});
