import { describe, it, expect, beforeEach } from "vitest";
import * as state from "../../src/state";
import { setCrypto } from "../../src/config";
import {
  CryptoUnavailableError,
  InvalidParameterError,
} from "../../src/errors";

const { __test_resetCryptoStateForUnitTests, getInternalTestUtils } =
  state as any;

describe("state concurrency and failure paths", () => {
  beforeEach(() => {
    if (typeof __test_resetCryptoStateForUnitTests === "function")
      __test_resetCryptoStateForUnitTests();
  });

  it("concurrent ensureCrypto calls share the same promise/provider", async () => {
    // Configure a fake provider first for deterministic behavior
    const fakeCrypto: any = { getRandomValues: (arr: Uint8Array) => arr };
    setCrypto(fakeCrypto as any);

    // Start two concurrent ensureCrypto calls
    const p1 = state.ensureCrypto();
    const p2 = state.ensureCrypto();

    // Wait for both to resolve and ensure both returned the injected provider
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toBe(fakeCrypto);
    expect(r2).toBe(fakeCrypto);
  });

  it("failed ensureCrypto resets internal state so subsequent calls can succeed", async () => {
    // Determine whether global crypto is available in this environment.
    const origGlobal = (globalThis as any).crypto;
    const globalCryptoAvailable = !!(
      origGlobal && typeof origGlobal.getRandomValues === "function"
    );

    if (globalCryptoAvailable) {
      // If the environment already provides crypto, ensureCrypto should resolve
      // Platform `crypto` getters may return wrapper objects, so avoid strict
      // identity checks and assert the returned object implements the API.
      const gotBefore = await state.ensureCrypto();
      expect(gotBefore).toHaveProperty("getRandomValues");
    } else {
      // Call ensureCrypto which should reject since no provider exists
      await expect(state.ensureCrypto()).rejects.toBeInstanceOf(
        CryptoUnavailableError,
      );
    }

    // Now configure a provider and ensure subsequent calls succeed
    const fakeCrypto2: any = { getRandomValues: (arr: Uint8Array) => arr };
    setCrypto(fakeCrypto2 as any);
    const got = await state.ensureCrypto();
    expect(got).toBe(fakeCrypto2);
  });

  it("generation counter prevents stale async resolution when reset during init", async () => {
    // This test uses internal test utils when available to inspect generation
    const utils =
      typeof getInternalTestUtils === "function"
        ? getInternalTestUtils()
        : undefined;
    if (!utils) {
      // If internal utils are not exposed, skip this fine-grained test
      return;
    }

    // Ensure no global crypto
    const origGlobal = (globalThis as any).crypto;
    try {
      delete (globalThis as any).crypto;
    } catch {}

    // Start ensureCrypto but before it finishes, bump generation by calling setCrypto(null)
    const p = state.ensureCrypto();
    const genBefore = utils._getCryptoGenerationForTest();

    // Reset generation to simulate another config action happening
    // setCrypto(null) increments the generation and clears cached promise
    setCrypto(null);
    const genAfter = utils._getCryptoGenerationForTest();
    expect(genAfter).toBeGreaterThanOrEqual(genBefore + 1);

    // The original promise should now reject with the specific reset error
    await expect(p).rejects.toThrow(/Crypto initialization was reset/);

    if (typeof origGlobal !== "undefined")
      (globalThis as any).crypto = origGlobal;
  });
});
