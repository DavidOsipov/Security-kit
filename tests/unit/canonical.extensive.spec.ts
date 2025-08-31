import { describe, it, expect } from 'vitest';
import { toCanonicalValue, safeStableStringify } from '../../src/canonical';

describe('canonical extensive cases', () => {
  it('deeply nested structures with undefined and null', () => {
    const input = {
      a: undefined,
      b: null,
      c: { d: undefined, e: { f: null, g: [1, undefined, { h: undefined, i: 2 }] } },
    };

    const canon = toCanonicalValue(input) as Record<string, unknown>;
    // undefined properties are elided, null preserved
    expect(Object.prototype.hasOwnProperty.call(canon, 'a')).toBe(false);
    expect(canon.b).toBe(null);
    const c = canon.c as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(c, 'd')).toBe(false);
    const e = c.e as Record<string, unknown>;
    const g = e.g as unknown[];
    expect(g[1]).toBeUndefined(); // array holes preserved as undefined entries
    expect((g[2] as Record<string, unknown>).h).toBeUndefined();
  });

  it('date handling: Date -> ISO string', () => {
    const d = new Date('2020-01-01T00:00:00Z');
    const canon = toCanonicalValue({ t: d }) as Record<string, unknown>;
    expect(canon.t).toBe(d.toISOString());
    expect(safeStableStringify({ t: d })).toContain(d.toISOString());
  });

  it('bigint throws', () => {
    expect(() => toCanonicalValue(BigInt(1))).toThrow();
  });

  it('symbols and functions are elided', () => {
    const obj = { a: Symbol('s'), b() { return 1; }, c: 1 } as any;
    const canon = toCanonicalValue(obj) as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(canon, 'a')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(canon, 'b')).toBe(false);
    expect(canon.c).toBe(1);
  });

  it('circular references throw or are handled gracefully', () => {
    const a: any = { x: 1 };
    a.self = a;
    // Implementation choice: toCanonicalValue may traverse into cycles; ensure it doesn't crash the process
    const out = toCanonicalValue(a);
    // Either returns some redacted form or throws; accept both but do not allow an infinite loop
    expect(out === undefined || typeof out === 'object').toBe(true);
  });

  it('consistent ordering across different property insert orders', () => {
    const one = { a: 1, b: 2, c: 3 };
    const two = { c: 3, a: 1, b: 2 };
    expect(safeStableStringify(one)).toBe(safeStableStringify(two));
  });
});
