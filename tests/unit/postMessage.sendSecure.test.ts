import { test, expect } from 'vitest';
import { sendSecurePostMessage } from '../../src/postMessage';
import { InvalidParameterError, TransferableNotAllowedError } from '../../src/errors';

test('sendSecurePostMessage rejects wildcard targetOrigin', () => {
  const fakeWin = { postMessage: () => {} } as unknown as Window;
  expect(() =>
    sendSecurePostMessage({ targetWindow: fakeWin, payload: {}, targetOrigin: '*' }),
  ).toThrow(InvalidParameterError);
});

test('sendSecurePostMessage rejects incompatible sanitize + allowTypedArrays', () => {
  const fakeWin = { postMessage: () => {} } as unknown as Window;
  expect(() =>
    sendSecurePostMessage({ targetWindow: fakeWin, payload: new Uint8Array([1, 2, 3]) as unknown, targetOrigin: location.origin, sanitize: true, allowTypedArrays: true, wireFormat: 'structured' as any }),
  ).toThrow(InvalidParameterError);
});

test('sendSecurePostMessage structured rejects ArrayBuffer when allowTypedArrays=false', () => {
  const fakeWin = { postMessage: () => {} } as unknown as Window;
  const buffer = new ArrayBuffer(8);
  expect(() =>
    sendSecurePostMessage({ targetWindow: fakeWin, payload: buffer as unknown, targetOrigin: location.origin, wireFormat: 'structured', allowTypedArrays: false }),
  ).toThrow(TransferableNotAllowedError);
});
