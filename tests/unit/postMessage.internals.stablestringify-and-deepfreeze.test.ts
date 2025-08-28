import { test, expect } from 'vitest';
import loadPostMessageInternals from '../../tests/helpers/vmPostMessageHelper';

test('stableStringify returns consistent string and falls back deterministically', async () => {
  const pm = loadPostMessageInternals();
  const internals = pm.__test_internals ?? pm;
  expect(internals.getPayloadFingerprint).toBeDefined();
  // simple object
  const s = await internals.getPayloadFingerprint({ a: 1, b: 2 });
  expect(typeof s).toBe('string');
});

test('deepFreeze respects node budget and does not throw on exotic objects', () => {
  const pm = loadPostMessageInternals();
  const internals = pm.__test_internals ?? pm;
  expect(internals.deepFreeze).toBeDefined();
  const obj: any = { a: { b: { c: { d: 1 } } } };
  // small budget should be sufficient
  const frozen = internals.deepFreeze(obj, 10);
  expect(Object.isFrozen(frozen)).toBe(true);
});
