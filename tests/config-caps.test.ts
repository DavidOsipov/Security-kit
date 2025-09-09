// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { setPostMessageConfig } from '../src/config';
import { InvalidParameterError } from '../src/errors';

describe('PostMessage config hard caps', () => {
  it('rejects values that exceed hard caps', () => {
    expect(() => setPostMessageConfig({ maxPayloadBytes: 1024 * 1024 })).toThrowError(
      InvalidParameterError,
    );
    expect(() => setPostMessageConfig({ maxTraversalNodes: 1_000_001 })).toThrowError(
      InvalidParameterError,
    );
    expect(() => setPostMessageConfig({ maxObjectKeys: 10_000 })).toThrowError(
      InvalidParameterError,
    );
    expect(() => setPostMessageConfig({ maxSymbolKeys: 1000 })).toThrowError(
      InvalidParameterError,
    );
    expect(() => setPostMessageConfig({ maxArrayItems: 10_000 })).toThrowError(
      InvalidParameterError,
    );
    expect(() => setPostMessageConfig({ maxTransferables: 1000 })).toThrowError(
      InvalidParameterError,
    );
  });

  it('accepts values within caps', () => {
    expect(() => setPostMessageConfig({ maxPayloadBytes: 64 * 1024 })).not.toThrow();
    expect(() => setPostMessageConfig({ maxTraversalNodes: 10_000 })).not.toThrow();
    expect(() => setPostMessageConfig({ maxObjectKeys: 256 })).not.toThrow();
    expect(() => setPostMessageConfig({ maxSymbolKeys: 32 })).not.toThrow();
    expect(() => setPostMessageConfig({ maxArrayItems: 512 })).not.toThrow();
    expect(() => setPostMessageConfig({ maxTransferables: 4 })).not.toThrow();
  });
});
