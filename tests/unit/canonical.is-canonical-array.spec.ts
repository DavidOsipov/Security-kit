import { describe, it, expect } from 'vitest';
import { toCanonicalValue, isCanonicalArray } from '../../src/canonical.ts';

describe('isCanonicalArray', () => {
  it('identifies canonicalized array', () => {
    const canon = toCanonicalValue([1,2,3]);
    expect(isCanonicalArray(canon)).toBe(true);
  });
  it('rejects normal array', () => {
    const arr = [1,2,3];
    expect(isCanonicalArray(arr)).toBe(false);
  });
  it('rejects frozen but prototype-backed array', () => {
    const arr = Object.freeze([1,2]);
    expect(isCanonicalArray(arr)).toBe(false);
  });
  it('rejects non-array', () => {
    expect(isCanonicalArray({})).toBe(false);
  });
});
