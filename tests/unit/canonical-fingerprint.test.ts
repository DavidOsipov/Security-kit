import { describe, it, expect } from 'vitest';
import { canonicalFingerprint, safeStableStringify, normalizeIdentifierString, UnicodeErrorCode } from '../../src/index.ts';
import { InvalidParameterError } from '../../src/errors.ts';

function extractUnicodeCode(e: unknown): string | undefined {
  if (!(e instanceof Error)) return undefined;
  const m = /\[code=(ERR_UNICODE_[A-Z_]+)\]/.exec(e.message);
  return m?.[1];
}

describe('canonicalFingerprint', () => {
  it('produces stable hash for same semantic object with different key order', () => {
    const a = { b: 1, a: 2 };
    const b = { a: 2, b: 1 };
    // canonicalization should order keys deterministically
    const fa = canonicalFingerprint(a);
    const fb = canonicalFingerprint(b);
    expect(fa).toEqual(fb);
  });

  it('changes when value changes', () => {
    const obj1 = { a: 1 };
    const obj2 = { a: 2 };
    expect(canonicalFingerprint(obj1)).not.toEqual(canonicalFingerprint(obj2));
  });
});

describe('Unicode surrogate rejection', () => {
  it('rejects lone high surrogate', () => {
    const loneHigh = '\uD800';
    let caught: unknown;
    try { normalizeIdentifierString(loneHigh, 'test'); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(InvalidParameterError);
    expect(extractUnicodeCode(caught)).toBe(UnicodeErrorCode.Surrogate);
  });

  it('rejects unpaired low surrogate', () => {
    const low = '\uDC00';
    let caught: unknown;
    try { normalizeIdentifierString(low, 'test'); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(InvalidParameterError);
    expect(extractUnicodeCode(caught)).toBe(UnicodeErrorCode.Surrogate);
  });

  it('accepts valid surrogate pair', () => {
    const musicalG = '\uD834\uDD1E'; // U+1D11E MUSICAL SYMBOL G CLEF
    expect(() => normalizeIdentifierString(musicalG, 'test')).not.toThrow();
  });
});

describe('safeStableStringify invariants', () => {
  it('is deterministic for nested objects', () => {
    const v1 = { z: 3, a: { b: 1, a: 2 } };
    const v2 = { a: { a: 2, b: 1 }, z: 3 };
    expect(safeStableStringify(v1)).toEqual(safeStableStringify(v2));
  });
});
