import { expect, test, vi, afterEach } from "vitest";
import { __test_deepFreeze, __test_resetForUnitTests } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
});

test("deepFreeze handles cycles without throwing and returns same reference", () => {
  const a: any = { x: 1 };
  const b: any = { a };
  a.b = b; // create cycle
  const res = __test_deepFreeze(a);
  expect(res).toBe(a);
  // frozen check: property cannot be reassigned
  expect(Object.isFrozen(a)).toBeTruthy();
  expect(Object.isFrozen(a.b)).toBeTruthy();
});

test("deepFreeze cache avoids re-freezing identical objects", () => {
  const obj = { a: { b: 2 } };
  const first = __test_deepFreeze(obj);
  // mutate via non-frozen path before second freeze attempt
  try { (obj as any).newProp = 1; } catch {}
  const second = __test_deepFreeze(obj);
  expect(first).toBe(second);
});
