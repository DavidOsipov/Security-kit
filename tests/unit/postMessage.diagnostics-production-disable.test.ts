import { expect, test, vi, afterEach } from "vitest";
import {
  __test_getPayloadFingerprint,
  __test_resetForUnitTests,
} from "../../src/postMessage";
import * as state from "../../src/state";
import { environment } from "../../src/environment";
import * as utils from "../../src/utils";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try {
    __test_resetForUnitTests();
  } catch {}
  try {
    if (typeof (state as any).__test_resetCryptoStateForUnitTests === "function")
      (state as any).__test_resetCryptoStateForUnitTests();
  } catch {}
});

// Simulate production: set environment.isProduction true via stub
test("when in production and ensureCrypto rejects diagnostics are disabled", async () => {
  // Force production
  vi.spyOn(environment, "isProduction", "get").mockReturnValue(true as any);
  // ensureCrypto rejects
  vi.spyOn(state, "ensureCrypto").mockRejectedValue(new Error("no crypto"));

  // Spy on secureDevLog to capture logs; in production secureDevLog is a no-op
  const logSpy = vi.spyOn(utils, "secureDevLog");

  // call fingerprint (this will cause falling back and set diagnostics disabled flag)
  const fp = await __test_getPayloadFingerprint({ a: 1 });
  expect(typeof fp).toBe("string");

  // Subsequent attempt to schedule diagnostics should not attempt fingerprinting.
  // We simulate this by calling getPayloadFingerprint via the public test API again
  // after resetting ensureCrypto to a resolving stub and confirm secureDevLog was
  // not called with a fingerprint in later logs.
  vi.spyOn(state, "ensureCrypto").mockResolvedValue({
    getRandomValues: (arr: Uint8Array) => arr,
  } as unknown as Crypto);

  // trigger another fingerprint attempt
  const fp2 = await __test_getPayloadFingerprint({ b: 2 });
  expect(typeof fp2).toBe("string");

  // secureDevLog may be invoked for the fallback, but none of the calls should include a fingerprint
  expect(logSpy).toHaveBeenCalled();

  const anyWithFingerprint = (logSpy as any).mock.calls.some((c: any[]) => {
    return c.some((arg: any) => arg && arg.fingerprint);
  });
  expect(anyWithFingerprint).toBe(false);
});
