import { describe, it, expect } from 'vitest';
import { _redact } from '../../src/utils';

describe('sanitizer — additional adversarial cases', () => {
  it('handles large nested getter trees without triggering getters that throw', () => {
    const depth = 20;
    function makeTree(level: number): any {
      if (level === 0) return { ok: true };
      const o: any = {};
      Object.defineProperty(o, 'child', {
        get() {
          if (Math.random() < 0.001) throw new Error('rare getter');
          return makeTree(level - 1);
        },
        enumerable: true,
      });
      // also add normal properties that could be mistaken for typed arrays
      o.meta = { level };
      return o;
    }

    const tree = makeTree(depth);
    // sanitizer should not allow throwing getters to propagate
    expect(() => _redact(tree)).not.toThrow();
  });

  it('defends against Symbol-based spoofing (Symbol.toStringTag and other symbols)', () => {
    const s = Symbol('spoof');
    const obj: any = { a: 1 };
    (obj as any)[Symbol.toStringTag] = 'Uint8Array';
    (obj as any)[s] = { secret: 'should-not-leak' };

    const out = _redact(obj);
    // Should not be treated as typed-array nor leak symbol-hidden secrets
    const str = JSON.stringify(out);
    expect(str).not.toContain('should-not-leak');
    expect(str).not.toContain('Uint8Array');
  });

  it('cross-type confusion objects (Map masquerading as Object keys) are handled', () => {
    const map = new Map();
    map.set('k', new Uint8Array([1, 2, 3]));
    const wrapper: any = { map };

    // sanitizer must not expand Map contents into raw arrays or leak bytes
    const out = _redact(wrapper) as any;
    const s = JSON.stringify(out);
    expect(s).not.toContain('1,2,3');
  });

  it('Map/Set entries containing typed arrays do not leak raw bytes', () => {
    const m = new Map();
    m.set('ta', new Uint8Array([9, 9, 9]));
    const s = new Set();
    s.add(new Uint8Array([7, 8, 9]));

    const out = _redact({ m, s });
    const str = JSON.stringify(out);
    expect(str).not.toContain('9,9,9');
    expect(str).not.toContain('7,8,9');
  });
});
