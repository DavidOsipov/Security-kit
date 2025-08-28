import { test, expect } from 'vitest';
import loadPostMessageInternals from '../../tests/helpers/vmPostMessageHelper';

// This test compiles a temporary copy of src/postMessage.ts with a build-time
// macro `__TEST__ = true` so the IIFE that exposes `__test_internals` runs.
// It runs the transpiled code in an isolated VM so we don't mutate the real
// module cache.

test('build-time __TEST__ exposes __test_internals when compiled with macro', async () => {
  const pm = loadPostMessageInternals();
  expect(pm.__test_internals).toBeDefined();
  const internals = pm.__test_internals;
  expect(typeof internals.toNullProto).toBe('function');
  const res = internals.toNullProto({ a: 1, __proto__: { polluted: true } });
  expect(res).toBeDefined();
});
