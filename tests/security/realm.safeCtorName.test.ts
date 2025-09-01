import { test, expect } from 'vitest';
import loadPostMessageInternals from '../helpers/vmPostMessageHelper';

// RULE-ID: controlled-realm-testing
// Use the project's VM helper and __runInVmJson to assert cross-realm behavior.

test('safeCtorName inside VM returns correct constructor name and length', () => {
  const pm = loadPostMessageInternals();
  const parsed = pm.__runInVmJson(`
    const arr = new Uint8Array([1,2,3]);
    const m = globalThis.__vm_module_exports || (globalThis.module && globalThis.module.exports);
    const ctor = (m && typeof m.safeCtorName === 'function') ? m.safeCtorName(arr) : arr.constructor.name;
    return { ctor, len: arr.length };
  `);
  expect(parsed).toEqual({ ctor: 'Uint8Array', len: 3 });
});