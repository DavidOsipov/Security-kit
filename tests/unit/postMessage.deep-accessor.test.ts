import { expect, test, afterEach } from "vitest";
import { __test_toNullProto, __test_resetForUnitTests } from "../../src/postMessage";

(globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

afterEach(() => {
  try {
    __test_resetForUnitTests();
  } catch {}
});

test("deep accessor that throws is skipped and other properties preserved", () => {
  const nested = { ok: { fine: 1 } } as any;
  Object.defineProperty(nested.ok, "bad", {
    enumerable: true,
    get() {
      throw new Error("boom deep");
    },
  });
  const src = { top: { nested } };

  const res = __test_toNullProto(src) as any;
  // Ensure top.nested.ok.fine preserved
  expect(res.top.nested.ok.fine).toBe(1);
  // The accessor 'bad' should not be present
  expect(Object.hasOwn(res.top.nested.ok, "bad")).toBe(false);
});
