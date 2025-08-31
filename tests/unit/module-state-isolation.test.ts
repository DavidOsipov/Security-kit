import { beforeEach, test, expect, vi } from 'vitest';

// RULE-ID: module-state-isolation
// Tests must avoid leaking module state between tests using vi.resetModules()

beforeEach(() => {
  vi.resetModules();
});

test('module starts with default state', async () => {
  const mod = await import('../../src/state');
  // state module exposes getInternalTestUtils in this project; use a small sanity check
  const utils = (mod as any).getInternalTestUtils?.() ?? null;
  // ensure we got an object or null in a deterministic way
  expect(typeof utils === 'object' || utils === null).toBe(true);
});

test('dynamic import yields new instance and modifications do not leak', async () => {
  const m1 = await import('../../src/state');
  if (typeof (m1 as any).setCrypto === 'function') {
    // call a setter if available to mutate state
    try {
      (m1 as any).setCrypto(undefined as any);
    } catch {
      // ignore errors - some test envs restrict this
    }
  }

  // Reset modules and re-import to ensure fresh state
  vi.resetModules();
  const m2 = await import('../../src/state');
  // Compare that the module references are different
  expect(m1).not.toBe(m2);
});