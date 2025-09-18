import { describe, it, expect } from 'vitest';
import { normalizeIdentifierString } from '../../src/index.ts';
import { InvalidParameterError, UnicodeErrorCode } from '../../src/errors.ts';

function codeOf(e: unknown): string | undefined {
  if (!(e instanceof Error)) return undefined;
  const m = /\[code=(ERR_UNICODE_[A-Z_]+)\]/.exec(e.message);
  return m?.[1];
}

describe('Unicode core unit guards', () => {
  it('rejects bidi control character', () => {
    try { normalizeIdentifierString('\u202Eabc', 'bidi'); } catch (e) {
      expect(e).toBeInstanceOf(InvalidParameterError);
      expect(codeOf(e)).toBe(UnicodeErrorCode.Bidi);
      return;
    }
    throw new Error('Expected rejection');
  });
  it('rejects zero-width space', () => {
    try { normalizeIdentifierString('a\u200B', 'inv'); } catch (e) {
      expect(codeOf(e)).toBe(UnicodeErrorCode.Invisible);
      return;
    }
    throw new Error('Expected rejection');
  });
  it('rejects excessive combining run', () => {
    const payload = 'a' + '\u0301'.repeat(10);
    try { normalizeIdentifierString(payload, 'comb'); } catch (e) {
      expect(codeOf(e)).toBe(UnicodeErrorCode.Combining);
      return;
    }
    throw new Error('Expected combining rejection');
  });
  it('rejects introduction of structural chars via normalization', () => {
    // Use FULLWIDTH SLASH U+FF0F which normalizes to '/'
    const payload = '\uFF0F';
    try { normalizeIdentifierString(payload, 'struct'); } catch (e) {
      expect(codeOf(e)).toBe(UnicodeErrorCode.Structural);
      return; }
    throw new Error('Expected structural introduction rejection');
  });
});
