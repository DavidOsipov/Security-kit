import { describe, it, expect } from 'vitest';
import loadPostMessageInternals from '../helpers/vmPostMessageHelper';

describe('vmPostMessageHelper.__runInVmJson', () => {
  it('returns arrays from VM code', () => {
    const pm = loadPostMessageInternals();
    const res = pm.__runInVmJson(`
      const a = new Uint8Array([1,2,3]);
      return Array.from(a);
    `);
    expect(res).toEqual([1,2,3]);
  });

  it('returns strings from VM code', () => {
    const pm = loadPostMessageInternals();
    const res = pm.__runInVmJson(`
      return JSON.stringify({ok: true});
    `);
    expect(res).toBe('{"ok":true}');
  });

  it('returns error markers when VM code throws', () => {
    const pm = loadPostMessageInternals();
    const res = pm.__runInVmJson(`
      throw new Error('boom');
    `);
    // helper returns a string starting with __RUN_ERROR__ or undefined
    expect(res === undefined || (typeof res === 'string' && res.includes('boom'))).toBe(true);
  });
});
