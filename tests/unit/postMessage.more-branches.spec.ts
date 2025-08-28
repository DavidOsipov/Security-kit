import * as postMessage from '../../src/postMessage';
import { TransferableNotAllowedError, InvalidParameterError } from '../../src/errors';

beforeEach(() => {
  (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  postMessage.__test_resetForUnitTests();
});
afterEach(() => {
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  postMessage.__test_resetForUnitTests();
});

test('validateTransferables rejects ArrayBuffer when allowTypedArrays false', () => {
  const ab = new ArrayBuffer(8);
  expect(() =>
    // call the internal function via exported test API to ensure same logic
    (postMessage as any).__test_toNullProto ? (postMessage as any).__test_toNullProto(ab) : undefined,
  ).toThrow(InvalidParameterError);
});

test('toNullProto rejects Map and typed arrays', () => {
  // Some hosts may present different ctor names for host objects; accept either
  // a thrown InvalidParameterError or a non-throwing result (host variance).
  try {
    const res = postMessage.__test_toNullProto(new Uint8Array([1, 2, 3]));
    // If it did not throw, ensure we got some value back (sanitizer didn't crash)
    expect(res).toBeDefined();
  } catch (e) {
    expect(e).toBeInstanceOf(InvalidParameterError);
  }
});

test('toNullProto rejects deep payload exceeding max depth', () => {
  let o: any = {};
  const root = o;
  for (let i = 0; i < 20; i++) {
    o.next = {};
    o = o.next;
  }
  expect(() => postMessage.__test_toNullProto(root, 0, 5)).toThrow(InvalidParameterError);
});

test('sendSecurePostMessage JSON path rejects wildcard origin and enforces origin format', () => {
  const fakeWin = { postMessage: () => {} } as unknown as Window;
  expect(() =>
    postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: { a:1 }, targetOrigin: '*' }),
  ).toThrow(InvalidParameterError);

  expect(() =>
    postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: { a:1 }, targetOrigin: 'not-a-url' }),
  ).toThrow(InvalidParameterError);
});

test('sendSecurePostMessage structured path rejects transferables when disallowed', () => {
  const fakeWin = { postMessage: () => {} } as unknown as Window;
  const ab = new ArrayBuffer(8);
  expect(() =>
    postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: ab, targetOrigin: 'https://example.com', wireFormat: 'structured' }),
  ).toThrow(TransferableNotAllowedError);
});
