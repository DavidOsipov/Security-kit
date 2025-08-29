Cross-Realm Testing Guide

Purpose

This short guide shows the recommended way to write cross-realm tests using the project's VM helper. It explains why passing VM-created objects into the host test is brittle and demonstrates using __runInVmJson and __execInVm instead.

Why not pass VM objects to the host?

Objects created inside a Node VM are from a different realm: their prototypes and constructors differ from host objects. This makes instanceof checks, constructor name checks, and ArrayBuffer.isView brittle when performed on the host against VM objects. To avoid this, run realm-sensitive detection inside the VM and return JSON-serializable results to the host.

APIs exposed by the helper

- __runInVmJson(code: string): any
  Runs the provided code inside the VM and returns a JSON-serializable result (arrays, objects, strings) or an error marker. Use this for most cross-realm assertions.

- __execInVm(fnName: string, ...args): any
  Calls a named export from the module loaded in the VM with the provided args (marshaled) and returns the result.

- __runInVmUnsafe(code: string)
  Low-level runner that returns whatever the VM IIFE returns. This is intentionally named "Unsafe" and should not be used in normal tests. If you see calls to `__runInVm` they will now throw and guide you to migrate to `__runInVmJson`.

Example: asserting typed-array detection inside the VM

```js
import loadPostMessageInternals from '../../tests/helpers/vmPostMessageHelper';

it('detects typed arrays inside VM', () => {
  const pm = loadPostMessageInternals();
  const ctorName = pm.__runInVmJson(`
    return (function(){
      const a = new Uint8Array([1,2,3]);
      // call the internal helper that expects a VM-owned object
      return (typeof (globalThis.__vm_module_exports || module.exports).safeCtorName === 'function')
        ? (globalThis.__vm_module_exports || module.exports).safeCtorName(a)
        : 'NO_SAFE';
    })();
  `);
  expect(ctorName).toBe('Uint8Array');
});
```

Working with Vitest fake timers

When your test uses fake timers, forward or mock the timers into the VM so code that relies on setTimeout / setInterval works inside the VM. The helper already forwards host timers into the VM context by default. Use Vitest's fake timers at the start of the test and run pending timers when needed:

```js
import { vi } from 'vitest';
import loadPostMessageInternals from '../../tests/helpers/vmPostMessageHelper';

it('uses fake timers inside vm', async () => {
  vi.useFakeTimers();
  const pm = loadPostMessageInternals();

  const resPromise = Promise.resolve(pm.__runInVmJson(`
    return (function(){
      let called = false;
      setTimeout(() => { called = true; }, 100);
      return called;
    })();
  `));

  // advance timers in the host; VM saw the host's timers
  await vi.runAllTimersAsync();
  const res = await resPromise;
  expect(res).toBe(true);
  vi.useRealTimers();
});
```

Using module isolation (vi.resetModules + dynamic import)

If your test needs to import a module under a fresh module cache (for example to apply different env or global conditions), prefer the pattern below instead of top-level static imports:

```js
import { vi } from 'vitest';

it('loads module with fresh cache', async () => {
  vi.resetModules();
  // set any globals or stubbed environment here
  const pm = (await import('../../tests/helpers/vmPostMessageHelper')).default();
  const result = pm.__runInVmJson(`return 1 + 1;`);
  expect(result).toBe(2);
});
```

Migration guidance

- `__runInVm` has been removed from the helper's public API to avoid accidental cross-realm object passing. Use `__runInVmJson(code)` in its place for most scenarios.
- If a test currently relies on the object identity across realms (rare), evaluate whether the check can instead be performed inside the VM and return a primitive result.
- If you absolutely must obtain a VM object reference in the host (advanced), the low-level runner remains available as `__runInVmUnsafe` but using it is discouraged because it is brittle across realms.

Further reading

See `docs/The Official Testing & Quality Assurance Constitution.md` for the project's formal rule on controlled-realm tests.
