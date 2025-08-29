import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe('postMessage internal test helpers (timestamp & deepFreeze)', () => {
  beforeEach(async () => {
    vi.resetModules();
    // Enable runtime test API guard used by postMessage test helpers
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    // Reset file-local state to ensure deterministic behavior
    const postMessage = await import('../../src/postMessage');
    postMessage.__test_resetForUnitTests();
  });

  afterEach(async () => {
    // Clean up the runtime guard
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    const postMessage = await import('../../src/postMessage');
    postMessage.__test_resetForUnitTests();
  });

  it('salt failure timestamp setters/getters and reset behavior', async () => {
    const postMessage = await import('../../src/postMessage');
    // Initially undefined
    expect(postMessage.__test_getSaltFailureTimestamp()).toBeUndefined();

    // Set a timestamp and read it back
    postMessage.__test_setSaltFailureTimestamp(42);
    expect(postMessage.__test_getSaltFailureTimestamp()).toBe(42);

    // Reset clears it
    postMessage.__test_resetForUnitTests();
    expect(postMessage.__test_getSaltFailureTimestamp()).toBeUndefined();
  });

  it('deepFreeze returns same object and attempts to freeze', async () => {
    const postMessage = await import('../../src/postMessage');
    const obj = { a: { b: 1 } };
    const res = postMessage.__test_deepFreeze(obj);
    // deepFreeze should return the same reference
    expect(res).toBe(obj);
    // At least the top-level object should be frozen (best-effort)
    expect(Object.isFrozen(res)).toBeTruthy();
  });
});
