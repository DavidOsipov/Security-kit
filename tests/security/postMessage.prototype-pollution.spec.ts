import { expect, test, vi, afterEach } from "vitest";
import { __test_toNullProto, __test_resetForUnitTests } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  vi.restoreAllMocks();
  try { __test_resetForUnitTests(); } catch {}
});

test("toNullProto removes prototype manipulation keys and skips accessors", () => {
  const obj: any = {
    safe: 1,
    __proto__: { polluted: true },
    constructor: "bad",
  };
  Object.defineProperty(obj, "evil", {
    get() { throw new Error("accessor called"); },
    enumerable: true,
  });
  const sanitized = __test_toNullProto(obj) as any;
  expect(Object.getPrototypeOf(sanitized)).toBeNull();
  expect(sanitized.safe).toBe(1);
  expect(sanitized.constructor).toBeUndefined();
  expect(sanitized.__proto__).toBeUndefined();
  expect(sanitized.evil).toBeUndefined();
});
