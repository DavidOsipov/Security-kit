import { expect, test, afterEach } from "vitest";
import {
  __test_deepFreeze,
  __test_resetForUnitTests,
} from "../../src/postMessage";

afterEach(() => {
  try {
    __test_resetForUnitTests();
  } catch {}
});

// Allow test APIs at runtime
(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

test("deepFreeze freezes objects and is idempotent via cache", () => {
  const obj: any = { a: { b: 1 } };
  const frozen = __test_deepFreeze(obj);
  expect(Object.isFrozen(frozen)).toBe(true);
  expect(Object.isFrozen(frozen.a)).toBe(true);

  // calling again should be harmless (idempotent)
  const frozen2 = __test_deepFreeze(frozen);
  expect(frozen2).toBe(frozen);
});

test("deepFreeze handles cyclic objects without throwing", () => {
  const a: any = {};
  const b: any = { a };
  a.b = b;
  // Should not throw
  expect(() => __test_deepFreeze(a)).not.toThrow();
});
