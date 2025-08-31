import { test, expect } from 'vitest';
import {
  validateTransferables,
  sendSecurePostMessage,
  createSecurePostMessageListener,
  __test_toNullProto,
  POSTMESSAGE_MAX_PAYLOAD_BYTES,
} from '../../src/postMessage';
import { environment } from '../../src/environment';
import { TransferableNotAllowedError, InvalidParameterError, InvalidConfigurationError } from '../../src/errors';

test('validateTransferables rejects MessagePort-like objects when not allowed', () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
  // craft an object whose prototype constructor.name === 'MessagePort'
  class MessagePort {}
  const obj = Object.create(MessagePort.prototype);
    obj.x = 1;

    expect(() =>
      validateTransferables(obj, /* allowTransferables */ false, /* allowTypedArrays */ false),
    ).toThrow(TransferableNotAllowedError);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});

test('validateTransferables allows MessagePort-like objects when allowed', () => {
  class MessagePort {}
  const obj = Object.create(MessagePort.prototype);
  obj.x = 1;
  expect(() =>
    validateTransferables(obj, /* allowTransferables */ true, /* allowTypedArrays */ false),
  ).not.toThrow();
});

test('sendSecurePostMessage JSON path sends serialized string and enforces size', () => {
  const posted: Array<{ data: unknown; origin: string }> = [];
  const fakeWin = {
    postMessage(this: unknown, data: unknown, origin: string) {
      posted.push({ data, origin });
    },
  } as unknown as Window;

  // small payload should be serialized and posted
  sendSecurePostMessage({ targetWindow: fakeWin, payload: { a: 1 }, targetOrigin: location.origin });
  expect(posted.length).toBe(1);
  expect(typeof posted[0].data).toBe('string');
  expect(posted[0].origin).toBe(location.origin);

  // oversized payload should throw
  const big = 'x'.repeat(POSTMESSAGE_MAX_PAYLOAD_BYTES + 10);
  expect(() =>
    sendSecurePostMessage({ targetWindow: fakeWin, payload: big, targetOrigin: location.origin }),
  ).toThrow(InvalidParameterError);
});

test('createSecurePostMessageListener enforces production-time configuration requirements', () => {
  const prev = (environment as any).__explicitEnv;
  try {
    environment.setExplicitEnv('production');

    // Passing empty allowedOrigins array should cause InvalidConfigurationError
    expect(() =>
      createSecurePostMessageListener([], () => {}),
    ).toThrow(InvalidConfigurationError);

    // Passing allowed origins but no validator should also throw in production
    expect(() =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (createSecurePostMessageListener as any)(['http://localhost'], () => {}),
    ).toThrow(InvalidConfigurationError);
  } finally {
    // restore environment
    try {
      environment.setExplicitEnv(prev === undefined ? 'development' : prev);
    } catch {
      /* ignore */
    }
  }
});

test('toNullProto strips forbidden keys like __proto__', () => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  try {
    const input = { good: 1, __proto__: { polluted: true } } as unknown as Record<string, unknown>;
    const out = __test_toNullProto(input) as Record<string, unknown>;
    expect(out.good).toBe(1);
    expect(Object.hasOwn(out, '__proto__')).toBe(false);
  } finally {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  }
});
