import { describe, it, expect } from 'vitest';
import { _redact } from '../../src/utils';

// Extended fuzz / randomized prototype-pollution trials.
// Gated behind RUN_FUZZ=1 environment variable to avoid running in regular CI.

const shouldRun = process.env.RUN_FUZZ === '1';
const LIMIT = Number(process.env.RUN_FUZZ_LIMIT || 5000);

function pseudoRandom(seed: number) {
  let s = seed >>> 0;
  return () => {
    // xorshift32
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0xffffffff;
  };
}

describe('fuzz (extensive) — sanitizer (gated)', () => {
  if (!shouldRun) {
    it('skipped (set RUN_FUZZ=1 to run)', () => {
      console.info('RUN_FUZZ not set — skipping extensive sanitizer fuzz test');
      expect(true).toBe(true);
    });
    return;
  }

  it(
    'deterministic long-run: many structured inputs do not throw or leak',
    () => {
      const rand = pseudoRandom(0xDEADBEEF);
      for (let i = 0; i < Math.min(LIMIT, 20000); i++) {
        const k = `k_${(i ^ Math.floor(rand() * 0xffffffff)).toString(16)}`;
        const r = rand();
        let v: any;
        if (r < 0.2) v = { a: Math.floor(rand() * 1e6) };
        else if (r < 0.4) v = `s_${Math.floor(rand() * 1e6)}`;
        else if (r < 0.6) v = null;
        else if (r < 0.8) v = new Uint8Array([Math.floor(rand() * 256)]);
        else v = { toJSON() { if (rand() < 0.01) throw new Error('fuzz toJSON'); return { n: 1 }; } };

        const obj: any = {};
        obj[k] = v;
        expect(() => _redact(obj)).not.toThrow();
        const out = _redact(obj) as any;
        // if typed-array, ensure not expanded to array
        if (v && ArrayBuffer.isView(v)) {
          expect(Array.isArray(out[k])).toBe(false);
        }
      }
    },
    { timeout: 120000 },
  );

  it(
    'randomized prototype-pollution trials (gated)',
    () => {
      const rand = pseudoRandom(0xFEEDFACE);
      const trials = Math.min(LIMIT, 5000);
      for (let t = 0; t < trials; t++) {
        const target = ['Object', 'Array', 'Uint8Array', 'Map', 'Set'][Math.floor(rand() * 5)];
        const key = `p_${Math.floor(rand() * 1e9).toString(16)}`;
        try {
          // Attempt to set a dangerous property on a prototype and then run sanitizer
          // Avoid permanent pollution: snapshot and restore
          const proto = (globalThis as any)[target] && (globalThis as any)[target].prototype;
          if (!proto) continue;
          const prev = proto[key];
          try {
            Object.defineProperty(proto, key, {
              value: `injected_${t}`,
              configurable: true,
              enumerable: false,
              writable: true,
            });

            const obj: any = { a: 1, b: new Uint8Array([1, 2, 3]) };
            // run sanitizer; must not throw and must not include injected_...
            const out = _redact(obj);
            expect(() => JSON.stringify(out)).not.toThrow();
            expect(JSON.stringify(out)).not.toContain(`injected_${t}`);
          } finally {
            if (typeof prev === 'undefined') delete (proto as any)[key];
            else (proto as any)[key] = prev;
          }
        } catch (err) {
          // If sanitizer throws for some reason, fail the test: the sanitizer must be robust.
          throw err;
        }
      }
    },
    { timeout: 120000 },
  );
});
