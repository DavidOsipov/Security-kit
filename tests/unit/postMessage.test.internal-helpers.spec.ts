import * as postMessage from '../../src/postMessage';

describe('postMessage internal test helpers (timestamp & deepFreeze)', () => {
  beforeEach(() => {
    // Enable runtime test API guard used by postMessage test helpers
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    // Reset file-local state to ensure deterministic behavior
    postMessage.__test_resetForUnitTests();
  });

  afterEach(() => {
    // Clean up the runtime guard
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    postMessage.__test_resetForUnitTests();
  });

  test('salt failure timestamp setters/getters and reset behavior', () => {
    // Initially undefined
    expect(postMessage.__test_getSaltFailureTimestamp()).toBeUndefined();

    // Set a timestamp and read it back
    postMessage.__test_setSaltFailureTimestamp(42);
    expect(postMessage.__test_getSaltFailureTimestamp()).toBe(42);

    // Reset clears it
    postMessage.__test_resetForUnitTests();
    expect(postMessage.__test_getSaltFailureTimestamp()).toBeUndefined();
  });

  test('deepFreeze returns same object and attempts to freeze', () => {
    const obj = { a: { b: 1 } };
    const res = postMessage.__test_deepFreeze(obj);
    // deepFreeze should return the same reference
    expect(res).toBe(obj);
    // At least the top-level object should be frozen (best-effort)
    expect(Object.isFrozen(res)).toBeTruthy();
  });
});
