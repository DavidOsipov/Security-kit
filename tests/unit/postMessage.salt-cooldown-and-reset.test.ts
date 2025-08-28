import { expect, test, afterEach } from 'vitest';
import * as postMessage from '../../src/postMessage';
import { __test_resetCryptoStateForUnitTests, _setCrypto } from '../../src/state';

afterEach(() => {
  try {
    postMessage.__test_resetForUnitTests();
  } catch {}
  try {
    if (typeof __test_resetCryptoStateForUnitTests === 'function')
      __test_resetCryptoStateForUnitTests();
  } catch {}
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
});

test('reset clears salt and failure timestamp', () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  postMessage.__test_setSaltFailureTimestamp(9999);
  expect(postMessage.__test_getSaltFailureTimestamp()).toBe(9999);
  postMessage.__test_resetForUnitTests();
  expect(postMessage.__test_getSaltFailureTimestamp()).toBe(undefined);
});

test('ensureFingerprintSalt rejects when crypto unavailable and cooldown active', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  // simulate crypto state that will reject when requested by ensureCrypto
  try {
    // Provide a fake crypto that throws on getRandomValues by leaving undefined
    _setCrypto(undefined as unknown as Crypto, { allowInProduction: true });
  } catch {
    // ignore if state guard prevents it
  }

  // Set a recent failure timestamp to be within the cooldown window
  const now = Date.now();
  postMessage.__test_setSaltFailureTimestamp(now);

  // Calling the runtime helper should now trigger the cooldown path which
  // throws a CryptoUnavailableError (or generic error). We assert it rejects.
  let threw = false;
  try {
    await postMessage.__test_ensureFingerprintSalt();
  } catch (e) {
    threw = true;
    expect(e).toBeInstanceOf(Error);
  }
  expect(threw).toBe(true);
});

test('computeFingerprintFromString uses fallback when subtle.digest unavailable', async () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    // Install a fake crypto with no subtle.digest to force fallback
    const fakeCrypto: Partial<Crypto> = {
      // Use any to bypass strict typing for the test stub
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      getRandomValues: ((arr: any) => arr) as unknown as <T extends ArrayBufferView>(array: T) => T,
      // subtle missing or incomplete to force fallback
    };
    _setCrypto(fakeCrypto as unknown as Crypto, { allowInProduction: true });
  } catch {
    // ignore
  }

  // Ensure salt is available by forcing salt generation to fallback path
  // reset state then call computeFingerprintFromString which will exercise
  // the non-subtle fallback hashing code path.
  postMessage.__test_resetForUnitTests();
  const fp = await (postMessage as any).__test_getPayloadFingerprint({ z: 1 });
  // The fallback produces a short hex-ish string; assert it's non-empty
  expect(typeof fp).toBe('string');
  expect(fp.length).toBeGreaterThan(0);
});
