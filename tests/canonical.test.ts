// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { safeStableStringify } from '../src/canonical';
import { setCanonicalConfig, _resetCanonicalConfigForTests } from '../src/config';
import { InvalidParameterError } from '../src/errors';

// Helper to build a deeply nested object to exhaust depth
function buildDeep(depth: number): unknown {
  let v: unknown = {};
  for (let i = 0; i < depth + 2; i++) {
    v = { a: v };
  }
  return v;
}

describe('canonicalization fail-closed and byte-precheck', () => {
  it('throws InvalidParameterError on depth exhaustion', () => {
    try {
      setCanonicalConfig({ maxDepth: 4 });
      const deep = buildDeep(10);
      expect(() => safeStableStringify(deep)).toThrowError(InvalidParameterError);
    } finally {
      _resetCanonicalConfigForTests();
    }
  });

  it('uses byte length (UTF-8) for string precheck', () => {
    try {
      setCanonicalConfig({ maxStringLengthBytes: 4 });
      // 3-byte UTF-8 character repeated twice makes 6 bytes
      const s = '€€';
      expect(() => safeStableStringify(s)).toThrowError(InvalidParameterError);
    } finally {
      _resetCanonicalConfigForTests();
    }
  });
});
