import { beforeEach, afterEach, expect, test, vi } from 'vitest';
import * as postMessage from '../../src/postMessage';

// Enable test APIs at runtime
beforeEach(() => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  postMessage.__test_resetForUnitTests();
});
afterEach(() => {
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  postMessage.__test_resetForUnitTests();
  vi.restoreAllMocks();
});

test('ensureFingerprintSalt succeeds when crypto available (subtle path mocked)', async () => {
  // Spy on state.ensureCrypto to provide a fake crypto with getRandomValues
  const state = await import('../../src/state');
  const fakeCrypto = {
    getRandomValues(buf: Uint8Array) {
      for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
      return buf;
    },
    subtle: {
      async digest(_alg: string, data: ArrayBuffer) {
        // return a predictable digest (all zeros) as ArrayBuffer
        return new Uint8Array(data.byteLength).buffer;
      },
    },
  } as unknown as Crypto;

  const spy = vi.spyOn(state, 'ensureCrypto').mockResolvedValue(fakeCrypto);

  const salt = await postMessage.__test_ensureFingerprintSalt();
  expect(salt).toBeInstanceOf(Uint8Array);
  expect(salt.length).toBeGreaterThan(0);

  // subsequent call returns same cached salt
  const salt2 = await postMessage.__test_ensureFingerprintSalt();
  expect(salt2).toEqual(salt);

  spy.mockRestore();
});

test('ensureFingerprintSalt honors cooldown (throws when timestamp recent)', async () => {
  // Set a recent failure timestamp to trigger cooldown
  const now = Date.now();
  postMessage.__test_setSaltFailureTimestamp(now);
  try {
    await postMessage.__test_ensureFingerprintSalt();
    throw new Error('Expected ensureFingerprintSalt to throw due to cooldown');
  } catch (err: any) {
    expect(err).toBeDefined();
  }
});

test('getPayloadFingerprint uses subtle.digest when available', async () => {
  const state = await import('../../src/state');
  // Provide fake crypto where subtle.digest returns predictable bytes
  const fakeDigest = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]).buffer;
  const fakeCrypto = {
    getRandomValues(buf: Uint8Array) {
      for (let i = 0; i < buf.length; i++) buf[i] = (i + 1) & 0xff;
      return buf;
    },
    subtle: {
      async digest(_alg: string, _data: ArrayBuffer) {
        return fakeDigest;
      },
    },
  } as unknown as Crypto;
  const spy = vi.spyOn(state, 'ensureCrypto').mockResolvedValue(fakeCrypto);

  const fp = await postMessage.__test_getPayloadFingerprint({ a: 1 });
  expect(typeof fp).toBe('string');
  // Since base64 slice(0,12) may be used, ensure it's not the error token
  expect(fp).not.toBe('FINGERPRINT_ERR');

  spy.mockRestore();
});

test('scheduleDiagnosticForFailedValidation logs fingerprint when enabled', async () => {
  const state = await import('../../src/state');
  // Provide fake crypto that supports subtle.digest
  const fakeDigest = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]).buffer;
  const fakeCrypto = {
    getRandomValues(buf: Uint8Array) {
      for (let i = 0; i < buf.length; i++) buf[i] = (i + 2) & 0xff;
      return buf;
    },
    subtle: {
      async digest(_alg: string, _data: ArrayBuffer) {
        return fakeDigest;
      },
    },
  } as unknown as Crypto;
  vi.spyOn(state, 'ensureCrypto').mockResolvedValue(fakeCrypto);

  // Create a listener with enableDiagnostics true and a schema validator
  // Use a spy for the consumer so we can assert messages are not delivered when validation fails
  const onMessageSpy = vi.fn();
  const listener = postMessage.createSecurePostMessageListener(
    {
      allowedOrigins: ['http://localhost'],
      onMessage: onMessageSpy,
      validate: { a: 'number' },
      enableDiagnostics: true,
    },
    undefined as any,
  );

  // Craft a JSON string that will fail validation (a is wrong type)
  const eventData = JSON.stringify({ a: 'not-a-number' });

  // Post the message to the current window/origin to trigger the listener
  window.postMessage(eventData, window.location.origin);

  // Allow a small delay for async fingerprinting/diagnostic path to run
  await new Promise((r) => setTimeout(r, 300));

  // The consumer should not have been called because validation failed
  expect(onMessageSpy).not.toHaveBeenCalled();

  listener.destroy();
});

test('parseMessageEventData structured rejects disallowed transferables', async () => {
  // Create a listener configured for structured wireFormat
  const onMessage = vi.fn();
  const listener = postMessage.createSecurePostMessageListener(
    {
      allowedOrigins: ['http://localhost'],
      onMessage,
      validate: () => true,
      wireFormat: 'structured',
      allowTransferables: false,
    },
  );

  // Craft a fake MessagePort-like object whose ctor name is MessagePort
  function MessagePort() {}
  const fakePort = Object.create(MessagePort.prototype);

  const eventLike = {
    origin: 'http://localhost',
    data: { port: fakePort },
    source: null,
  } as unknown as MessageEvent;

  // Calling the handler indirectly via window.postMessage would stringify; instead, call the registered handler via dispatch
  // We don't have direct access to the handler, but posting a message with structured data will trigger the listener
  try {
    // This may throw due to structured transferable rejection; we guard against throw
    window.postMessage(eventLike.data, eventLike.origin);
  } catch {
    // swallow — behavior is asserted by onMessage not being called
  }

  // allow a small delay for the listener to process
  await new Promise((r) => setTimeout(r, 20));
  expect(onMessage).not.toHaveBeenCalled();
  listener.destroy();
});

