// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { normalizeInputString } from '../../src/canonical.ts';
import { UnicodeErrorCode } from '../../src/errors.ts';

function extractCode(e: unknown): string | undefined {
  if (!(e instanceof Error)) return undefined;
  const m = e.message.match(/\[code=(ERR_UNICODE_[A-Z_]+)\]/);
  return m?.[1];
}

describe('Unicode surrogate & combining validation', () => {
  it('rejects lone high surrogate', () => {
    const s = '\uD834';
    try {
      normalizeInputString(s, 'test-high');
      expect.fail('Expected rejection');
    } catch (e) {
      expect(extractCode(e)).toBe(UnicodeErrorCode.Surrogate);
    }
  });
  it('rejects unpaired low surrogate', () => {
    const s = '\uDD1E';
    try {
      normalizeInputString(s, 'test-low');
      expect.fail('Expected rejection');
    } catch (e) {
      expect(extractCode(e)).toBe(UnicodeErrorCode.Surrogate);
    }
  });
  it('accepts valid surrogate pair (𝄞 U+1D11E)', () => {
    const s = '\uD834\uDD1E';
    const out = normalizeInputString(s, 'valid-pair');
    expect(out).toBe(s.normalize('NFKC'));
  });
  it('rejects excessive combining run', () => {
    const base = 'a';
    const run = base + '\u0301\u0301\u0301\u0301\u0301\u0301'; // 6 combining marks
    try {
      normalizeInputString(run, 'combining');
      expect.fail('Expected combining rejection');
    } catch (e) {
      expect(extractCode(e)).toBe(UnicodeErrorCode.Combining);
    }
  });
  it('allows safe combining within limit', () => {
    const base = 'a';
    const ok = base + '\u0301\u0301\u0301';
    const out = normalizeInputString(ok, 'combining-ok');
    expect(out).toBe(ok.normalize('NFKC'));
  });
});
