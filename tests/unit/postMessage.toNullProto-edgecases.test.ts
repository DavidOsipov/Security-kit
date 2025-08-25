import { expect, test, afterEach } from "vitest";
import {
  __test_toNullProto,
  __test_resetForUnitTests,
} from "../../src/postMessage";

afterEach(() => {
  try {
    __test_resetForUnitTests();
  } catch {}
});

// Allow test APIs at runtime
(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

test("toNullProto skips accessor properties that throw and preserves plain values", () => {
  const obj: Record<string, any> = { good: 1 };
  Object.defineProperty(obj, "bad", {
    enumerable: true,
    get() {
      throw new Error("boom");
    },
  });

  const res = __test_toNullProto(obj) as Record<string, unknown>;
  expect(res).toHaveProperty("good", 1);
  expect(Object.getPrototypeOf(res)).toBeNull();
  // accessor 'bad' should be skipped
  expect(Object.prototype.hasOwnProperty.call(res, "bad")).toBe(false);
});

test("toNullProto ignores symbol-keyed properties and removes forbidden names", () => {
  const sym = Symbol("secret");
  const src: Record<string, unknown> = { a: 1 };
  Object.defineProperty(src, sym as unknown as string, {
    enumerable: true,
    value: 42,
  });
  src["__proto__"] = "x";
  src["constructor"] = "x";
  src["prototype"] = "x";

  const res = __test_toNullProto(src) as Record<string, unknown>;
  // symbol keys must not be copied
  expect(Object.getOwnPropertySymbols(res).length).toBe(0);
  // forbidden keys removed
  expect(Object.prototype.hasOwnProperty.call(res, "__proto__")).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(res, "constructor")).toBe(false);
  expect(Object.prototype.hasOwnProperty.call(res, "prototype")).toBe(false);
  expect(res).toHaveProperty("a", 1);
});

test("toNullProto enforces depth limit and throws when exceeded", () => {
  const deep = { level1: { level2: { level3: { level4: 1 } } } };
  // set maxDepth low to force throw
  expect(() => __test_toNullProto(deep, 0, 1)).toThrow();
});
