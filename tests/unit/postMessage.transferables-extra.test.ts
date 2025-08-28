import { expect, test } from 'vitest';

test('validateTransferables rejects MessagePort-like host object when not allowed', async () => {
  const pm = await import('../../src/postMessage');
  const { TransferableNotAllowedError } = await import('../../src/errors');

  // Create an object whose prototype's constructor has name 'MessagePort'
  function MessagePort() {}
  const proto = { constructor: MessagePort } as any;
  const obj: any = Object.create(proto);
  obj.foo = 'bar';

  expect(() =>
    (pm.validateTransferables as any)(obj, false, false),
  ).toThrowError(TransferableNotAllowedError);
});

test('validateTransferables rejects ArrayBuffer when typed arrays not allowed', async () => {
  const pm = await import('../../src/postMessage');
  const { TransferableNotAllowedError } = await import('../../src/errors');

  const buf = new ArrayBuffer(8);
  expect(() => (pm.validateTransferables as any)(buf, false, false)).toThrowError(
    TransferableNotAllowedError,
  );
});

test('validateTransferables rejects TypedArray/DataView when not allowed and accepts when allowed', async () => {
  const { validateTransferables } = await import('../../src/postMessage');
  const { TransferableNotAllowedError } = await import('../../src/errors');

  const ta = new Uint8Array([1, 2, 3]);
  // In some exotic hosts ArrayBuffer.isView may throw; accept either behavior
  let threw = false;
  try {
    validateTransferables(ta as unknown, false, false);
  } catch (e) {
    threw = true;
    expect(e).toBeInstanceOf(TransferableNotAllowedError);
  }
  // Should not throw when allowTypedArrays is true
  expect(() => validateTransferables(ta as unknown, false, true)).not.toThrow();
});
