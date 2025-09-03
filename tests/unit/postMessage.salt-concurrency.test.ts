import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("postMessage fingerprint salt concurrency", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("memoizes salt promise so concurrent calls get the same salt", async () => {
    const state = await import("../../src/state");

    let callCount = 0;
    const fakeCrypto = {
      getRandomValues: (buf: Uint8Array) => {
        for (let i = 0; i < buf.length; i++) buf[i] = (i + 1) & 0xff;
        return buf;
      },
      subtle: { digest: async () => new Uint8Array([1]).buffer },
    } as any;
    vi.spyOn(state, "ensureCrypto").mockImplementation(async () => {
      callCount += 1;
      // small delay to force interleaving - uses real timers abstraction
      await new Promise((r) => setTimeout(r, 5));
      return fakeCrypto as any;
    });

    const postMessage = await import("../../src/postMessage");
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

    // Kick off multiple concurrent ensureFingerprintSalt via test accessor
    const p1 = postMessage.__test_ensureFingerprintSalt();
    const p2 = postMessage.__test_ensureFingerprintSalt();

    // advance fake timers so any pending delays in ensureCrypto resolve
    await vi.runAllTimersAsync();
    const [s1, s2] = await Promise.all([p1, p2]);

    expect(s1).toBeInstanceOf(Uint8Array);
    expect(s2).toBeInstanceOf(Uint8Array);
    // ensure underlying ensureCrypto was only called once
    expect(callCount).toBe(1);
    // salts equal
    expect(Array.from(s1)).toEqual(Array.from(s2));
  });
});
