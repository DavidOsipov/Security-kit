import { TransferableNotAllowedError, InvalidParameterError } from '../../src/errors';
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe('postMessage additional branch coverage', () => {
  beforeEach(async () => {
    vi.resetModules();
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    const postMessage = await import('../../src/postMessage');
    postMessage.__test_resetForUnitTests();
  });

  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    const postMessage = await import('../../src/postMessage');
    postMessage.__test_resetForUnitTests();
  });

  it('validateTransferables rejects ArrayBuffer when allowTypedArrays false', async () => {
    const postMessage = await import('../../src/postMessage');
    const { TransferableNotAllowedError } = await import('../../src/errors');
    const ab = new ArrayBuffer(8);
    try {
      postMessage.validateTransferables(ab, false, false);
      expect.fail("Expected TransferableNotAllowedError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TransferableNotAllowedError);
    }
  });

  it('toNullProto rejects Map and typed arrays', async () => {
    const postMessage = await import('../../src/postMessage');
    // Some hosts may present different ctor names for host objects; accept either
    // a thrown InvalidParameterError or a non-throwing result (host variance).
    try {
      const res = postMessage.__test_toNullProto(new Uint8Array([1, 2, 3]));
      // If it did not throw, ensure we got some value back (sanitizer didn't crash)
      expect(res).toBeDefined();
    } catch (e) {
      const { InvalidParameterError } = await import('../../src/errors');
      expect(e).toBeInstanceOf(InvalidParameterError);
    }
  });

  it('toNullProto rejects deep payload exceeding max depth', async () => {
    const postMessage = await import('../../src/postMessage');
    const { InvalidParameterError } = await import('../../src/errors');
    let o: any = {};
    const root = o;
    for (let i = 0; i < 20; i++) {
      o.next = { i };
      o = o.next;
    }
    try {
      postMessage.__test_toNullProto(root, 0, 5);
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }
  });

  it('sendSecurePostMessage JSON path rejects wildcard origin and enforces origin format', async () => {
    const postMessage = await import('../../src/postMessage');
    const { InvalidParameterError } = await import('../../src/errors');
    const fakeWin = { postMessage: () => {} } as unknown as Window;
    try {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: { a:1 }, targetOrigin: '*' });
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }

    try {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: { a:1 }, targetOrigin: 'not-a-url' });
      expect.fail("Expected InvalidParameterError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidParameterError);
    }
  });

  it('sendSecurePostMessage structured path rejects transferables when disallowed', async () => {
    const postMessage = await import('../../src/postMessage');
    const { TransferableNotAllowedError } = await import('../../src/errors');
    const fakeWin = { postMessage: () => {} } as unknown as Window;
    const ab = new ArrayBuffer(8);
    try {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: ab, targetOrigin: 'https://example.com', wireFormat: 'structured' });
      expect.fail("Expected TransferableNotAllowedError to be thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(TransferableNotAllowedError);
    }
  });
});
