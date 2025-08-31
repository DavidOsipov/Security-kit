import { describe, it, expect } from 'vitest';
import { toCanonicalValue, safeStableStringify } from '../../src/canonical';

describe('canonical primitives preservation', () => {
  it('preserves boolean true/false', () => {
    expect(toCanonicalValue(true)).toBe(true);
    expect(toCanonicalValue(false)).toBe(false);
    expect(safeStableStringify(true)).toBe('true');
    expect(safeStableStringify(false)).toBe('false');
  });

  it('preserves finite numbers', () => {
    expect(toCanonicalValue(1)).toBe(1);
    expect(toCanonicalValue(-3.14)).toBe(-3.14);
    expect(safeStableStringify(1)).toBe('1');
    expect(safeStableStringify(-3.14)).toBe('-3.14');
  });

  it('preserves strings', () => {
    expect(toCanonicalValue('abc')).toBe('abc');
    expect(safeStableStringify('abc')).toBe('"abc"');
  });

  it('preserves null distinctly from undefined', () => {
    expect(toCanonicalValue(null)).toBe(null);
    expect(safeStableStringify(null)).toBe('null');
  });

  it('converts non-finite numbers to undefined (elided)', () => {
    expect(toCanonicalValue(NaN)).toBe(undefined);
    expect(toCanonicalValue(Infinity)).toBe(undefined);
  });
});
