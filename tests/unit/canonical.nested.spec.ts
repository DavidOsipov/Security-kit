import { describe, it, expect } from 'vitest';
import { toCanonicalValue, safeStableStringify } from '../../src/canonical';

describe('canonical nested structures and prototype pollution', () => {
  it('canonicalizes nested objects with sorted keys and filters forbidden keys', () => {
    const input = {
      b: 2,
      a: { z: 1, y: "x", __proto__: { polluted: true }, c: [3, 1, { d: 4 }] },
    };

    const canonical = toCanonicalValue(input) as Record<string, unknown>;
    // top-level keys sorted
    expect(Object.keys(canonical)).toEqual(['a', 'b']);
    const a = canonical.a as Record<string, unknown>;
    // nested keys sorted
    expect(Object.keys(a)).toEqual(['c', 'y', 'z']);
  // forbidden key should not be present as an own property
  expect(Object.prototype.hasOwnProperty.call(a, '__proto__')).toBe(false);

    const s = safeStableStringify(input);
    // ensure deterministic representation
    expect(s).toContain('"a":');
    expect(s.indexOf('"a":')).toBeLessThan(s.indexOf('"b":'));
  });

  it('canonicalizes arrays preserving order and canonicalizing elements', () => {
    const input = [ { b:2, a:1 }, [3, 2, 1], "x" ];
    const c = toCanonicalValue(input) as unknown[];
    expect(Array.isArray(c)).toBe(true);
    // first element should have sorted keys
    expect(Object.keys(c[0] as object)).toEqual(['a','b']);
    // nested array order preserved
    expect(c[1]).toEqual([3,2,1]);
  });

  it('does not allow prototype pollution via __proto__/constructor/prototype keys', () => {
    const poisoned = JSON.parse('{"safe":1, "__proto__":{"polluted":true}}');
    const canon = toCanonicalValue(poisoned) as Record<string, unknown>;
  expect(Object.prototype.hasOwnProperty.call(canon, '__proto__')).toBe(false);
    expect(({} as any).polluted).toBeUndefined();
    // Ensure safe property present
    expect(canon.safe).toBe(1);
  });
});
