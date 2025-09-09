import { describe, it, expect } from 'vitest';
import { _redact, sanitizeLogMessage } from '../../src/utils';

describe('sanitizer — adversarial inputs', () => {
  it('handles prototype-pollution shaped objects without contaminating output', () => {
    const polluted: any = { a: 1 };
    polluted.__proto__ = { polluted: true };

    const out = _redact(polluted);
    // Should not leak prototype fields or copy __proto__ into output
    expect(JSON.stringify(out)).not.toContain('polluted');
  });

  it('handles objects with throwing getters safely', () => {
    const obj: any = {
      safe: 'ok',
    };
    Object.defineProperty(obj, 'evil', {
      get() {
        throw new Error('getter exploded');
      },
      enumerable: true,
    });

    // Should not throw; sanitizer must catch hostile getters
    expect(() => _redact(obj)).not.toThrow();
    const out = _redact(obj);
    expect(out).toHaveProperty('safe');
    // The hostile getter should not produce leaked values
    expect(JSON.stringify(out)).not.toContain('getter exploded');
  });

  it('sanitizes objects with malicious toJSON', () => {
    const obj: any = {
      name: 'bob',
      toJSON() {
        // pretend to leak an internal secret
        return { leaked: 'secret' };
      },
    };

    const out = _redact(obj);
    // toJSON should not allow leaking raw secret fields into sanitizer output
    expect(JSON.stringify(out)).not.toContain('secret');
  });

  it('does not reveal typed-array contents when prototype is tainted', () => {
    // Add a property on Int8Array.prototype to try to trick naive serializers
    // Note: do not permanently pollute global prototypes in test suites — restore after
    const proto = (Int8Array as any).prototype;
    const prev = proto.__leak_try;
    try {
      (proto as any).__leak_try = function () {
        return 'I should not be read';
      };

      const ta = new Int8Array([1, 2, 3, 4]);
      const out = _redact({ buffer: ta });
      const s = JSON.stringify(out);
      expect(s).not.toContain('1,2,3,4');
      expect(s).not.toContain('I should not be read');
    } finally {
      if (typeof prev === 'undefined') {
        delete (proto as any).__leak_try;
      } else {
        (proto as any).__leak_try = prev;
      }
    }
  });

  it('defends against Symbol.toStringTag spoofing and similar', () => {
    const obj: any = { a: 1 };
    Object.defineProperty(obj, Symbol.toStringTag, {
      value: 'Uint8Array',
      configurable: true,
    });

    const out = _redact(obj);
    // Should not be treated as a typed-array and leak raw bytes
    expect(JSON.stringify(out)).not.toContain('0,');
  });

  it('small deterministic fuzz loop: many odd keys and values do not throw or leak', () => {
    const seed = 0xC0FFEE;
    let s = seed;
    function rand() {
      // xorshift-ish deterministic
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      return Math.abs(s) >>> 0;
    }

    for (let i = 0; i < 256; i++) {
      const k = `k_${(rand() % 10000).toString(16)}`;
      const vChoice = rand() % 6;
      let v: any;
      switch (vChoice) {
        case 0:
          v = rand();
          break;
        case 1:
          v = `s_${rand()}`;
          break;
        case 2:
          v = { inner: rand() };
          break;
        case 3:
          const ta = new Uint8Array([(rand() & 0xff) >>> 0]);
          v = ta;
          break;
        case 4:
          v = { toJSON() { throw new Error('bad toJSON'); } };
          break;
        default:
          v = null;
      }

      const obj: any = {};
      obj[k] = v;
      // Should never throw
      expect(() => _redact(obj)).not.toThrow();
      const out = _redact(obj);
      // If value was a typed array, ensure contents are not present as plain numbers
      if (v && ArrayBuffer.isView(v)) {
        // Inspect sanitized output property by key to avoid key-name substring collisions
        const maybe = (out as any)[k];
        // The sanitizer should not expand typed arrays into plain JS arrays of numbers
        expect(Array.isArray(maybe)).toBe(false);
        // Additionally allow either an opaque string or an object with typed-array metadata
        const ok = typeof maybe === 'string' || (maybe && typeof maybe === 'object');
        expect(ok).toBe(true);
      }
    }
  });

  it('sanitizeLogMessage returns a string and does not leak secrets', () => {
    const secret = new Uint8Array([9, 8, 7]);
    const maybe = sanitizeLogMessage({ x: secret });
    expect(typeof maybe).toBe('string');
    expect(maybe).not.toContain('9');
    expect(maybe).not.toContain('8');
    expect(maybe).not.toContain('7');
  });
});
