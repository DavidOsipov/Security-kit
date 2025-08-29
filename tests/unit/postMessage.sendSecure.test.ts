import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { InvalidParameterError, TransferableNotAllowedError } from '../../src/errors';

describe('sendSecurePostMessage', () => {
  beforeEach(async () => {
    // Reset module cache before each test to ensure clean state
    vi.resetModules();
    // Allow test APIs in runtime by setting global flag
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
  });

  afterEach(async () => {
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    vi.restoreAllMocks();
  });

  it('rejects wildcard targetOrigin', async () => {
    const postMessage = await import('../../src/postMessage');
    const fakeWin = { postMessage: () => {} } as unknown as Window;
    expect(() => {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: {}, targetOrigin: '*' });
    }).toThrow('[security-kit] targetOrigin cannot be a wildcard');
  });

  it('rejects incompatible sanitize + allowTypedArrays', async () => {
    const postMessage = await import('../../src/postMessage');
    const fakeWin = { postMessage: () => {} } as unknown as Window;
    expect(() => {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: new Uint8Array([1, 2, 3]) as unknown, targetOrigin: location.origin, sanitize: true, allowTypedArrays: true, wireFormat: 'structured' as any });
    }).toThrow('Incompatible options: sanitize=true is incompatible with allowTypedArrays=true');
  });

  it('structured rejects ArrayBuffer when allowTypedArrays=false', async () => {
    const postMessage = await import('../../src/postMessage');
    const fakeWin = { postMessage: () => {} } as unknown as Window;
    const buffer = new ArrayBuffer(8);
    expect(() => {
      postMessage.sendSecurePostMessage({ targetWindow: fakeWin, payload: buffer as unknown, targetOrigin: location.origin, wireFormat: 'structured', allowTypedArrays: false });
    }).toThrow('ArrayBuffer is not allowed unless allowTypedArrays=true');
  });
});
