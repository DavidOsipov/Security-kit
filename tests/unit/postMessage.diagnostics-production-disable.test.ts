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
test("when in production and ensureCrypto rejects, fingerprinting is disabled and we fail loudly", async () => {
  // Force production
  vi.spyOn(environment, "isProduction", "get").mockReturnValue(true as any);
  // ensureCrypto rejects
  vi.spyOn(state, "ensureCrypto").mockRejectedValue(new Error("no crypto"));

  // Spy on secureDevLog to capture the warning log emitted before throwing
  const logSpy = vi.spyOn(utils, "secureDevLog");

  // call fingerprint: in production this must throw CryptoUnavailableError
  await expect(__test_getPayloadFingerprint({ a: 1 })).rejects.toThrow();

  // Ensure we logged a warning about disabling diagnostics in production
  expect(logSpy).toHaveBeenCalled();
  const anyWarn = (logSpy as any).mock.calls.some((c: any[]) => {
    return c[2] && String(c[2]).toLowerCase().includes("disabling diagnostics");
  });
  expect(anyWarn).toBe(true);
});
