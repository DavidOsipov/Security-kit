import * as postMessage from '../../src/postMessage';

test('direct salt timestamp set/get for coverage', () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    postMessage.__test_setSaltFailureTimestamp(1234);
    const v = postMessage.__test_getSaltFailureTimestamp();
    expect(v).toBe(1234);
  } finally {
    postMessage.__test_setSaltFailureTimestamp(undefined);
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
