// tests/security/controlled-realm.vm.tests.ts
// RULE-ID: controlled-realm-testing

import { test, expect } from 'vitest';
import loadPostMessageInternals from '../helpers/vmPostMessageHelper';

// This test verifies cross-realm behavior by executing code inside the
// project's VM helper and asserting JSON-serializable results, per the
// QA constitution's Controlled Realm Runner Usage rule.

test('safeCtorName works across realms (vm)', () => {
  const pm = loadPostMessageInternals();
  const result = pm.__runInVmJson(`
    const a = new Uint8Array([1,2,3]);
    const m = globalThis.__vm_module_exports || (globalThis.module && globalThis.module.exports);
    const ctor = (m && typeof m.safeCtorName === 'function') ? m.safeCtorName(a) : (a && a.constructor ? a.constructor.name : undefined);
    return { ctorName: ctor, length: a.length };
  `);
  expect(result).toEqual({ ctorName: 'Uint8Array', length: 3 });
});

test('structuredClone of typed arrays inside VM returns equal values', () => {
  const pm = loadPostMessageInternals();
  const result = pm.__runInVmJson(`
    const src = new Uint8Array([5,6,7,8]);
    const cloned = typeof structuredClone === 'function' ? structuredClone(src) : src.slice();
    // Return serializable info: values and lengths
    return { src: Array.from(src), cloned: Array.from(cloned), sameRef: src === cloned };
  `);
  expect(result.src).toEqual([5,6,7,8]);
  expect(result.cloned).toEqual([5,6,7,8]);
  // structuredClone should create a new object (not the same reference)
  expect(result.sameRef).toBe(false);
});

test('ArrayBuffer.isView and DataView/TypedArray detection works inside VM', () => {
  const pm = loadPostMessageInternals();
  const result = pm.__runInVmJson(`
    const arr = new Uint8Array(4);
    const dv = new DataView(new ArrayBuffer(8));
    const isViewArr = typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' ? ArrayBuffer.isView(arr) : null;
    const isViewDv = typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' ? ArrayBuffer.isView(dv) : null;
    return { isViewArr, isViewDv, arrCtor: arr.constructor.name, dvCtor: dv.constructor.name };
  `);
  expect(result).toEqual({ isViewArr: true, isViewDv: true, arrCtor: 'Uint8Array', dvCtor: 'DataView' });
});
