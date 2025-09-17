import { describe, it, expect } from 'vitest';
import { normalizeInputString } from '../../src/canonical.ts';

// We exploit an object whose JSON.stringify will throw via toJSON.

describe('UNSERIALIZABLE placeholder in _toString path', () => {
  it('returns [UNSERIALIZABLE] when JSON serialization fails', () => {
    const hostile = {
      toJSON() {
        throw new Error('nope');
      }
    };
    // normalization coerces input via internal _toString
    const out = normalizeInputString(hostile, 'unserializable-test');
    // If placeholder emitted, it will normalize to itself
    expect(out).toBe('[UNSERIALIZABLE]');
  });
});
