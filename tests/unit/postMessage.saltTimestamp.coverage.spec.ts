import { test, expect, vi } from "vitest";

test("direct salt timestamp set/get for coverage", async () => {
  vi.resetModules();
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    const postMessage = await import("../../src/postMessage");
    (postMessage as any).__test_setSaltFailureTimestamp(1234);
    const v = (postMessage as any).__test_getSaltFailureTimestamp();
    expect(v).toBe(1234);
  } finally {
    const postMessage = await import("../../src/postMessage");
    (postMessage as any).__test_setSaltFailureTimestamp(undefined);
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
