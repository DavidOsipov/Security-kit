// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { sendSecurePostMessage } from '../../src/postMessage.ts';
import { setPostMessageConfig } from '../../src/config.ts';
import { InvalidParameterError } from '../../src/errors.ts';

function makeTargetWindow(capture: { posted?: unknown }) {
  // Minimal Window-like shim for postMessage
  return {
    postMessage(data: unknown, _origin: string) {
      capture.posted = data;
    },
  } as unknown as Window;
}

describe('structured payload size enforcement (sanitize=false)', () => {
  it('rejects payloads exceeding maxPayloadBytes by byte-accurate check', () => {
    const capture: { posted?: unknown } = {};
    const target = makeTargetWindow(capture);
    setPostMessageConfig({ maxPayloadBytes: 32 }); // small cap

    // Multi-byte string: 3 bytes per char (e.g., U+20AC Euro sign) x 20 = 60 bytes
    const multi = '€'.repeat(20);

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        targetOrigin: 'https://example.com',
        wireFormat: 'structured',
        sanitize: false,
        payload: { s: multi },
      }),
    ).toThrowError(InvalidParameterError);

    expect(capture.posted).toBeUndefined();
  });

  it('allows small typed arrays when within cap and allowTypedArrays=true', () => {
    const capture: { posted?: unknown } = {};
    const target = makeTargetWindow(capture);
    setPostMessageConfig({ maxPayloadBytes: 1024 });

    const buf = new Uint8Array(64);

    expect(() =>
      sendSecurePostMessage({
        targetWindow: target,
        targetOrigin: 'https://example.com',
        wireFormat: 'structured',
        sanitize: false,
        payload: { a: buf },
        allowTypedArrays: true,
      }),
    ).not.toThrow();

    expect(capture.posted).toBeDefined();
  });
});
