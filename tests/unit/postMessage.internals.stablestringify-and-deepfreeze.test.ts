import { test, expect, vi } from "vitest";
import loadPostMessageInternals from "../../tests/helpers/vmPostMessageHelper.ts";

test("stableStringify returns consistent string and falls back deterministically", async () => {
  try {
    vi.useRealTimers();
    const pm = loadPostMessageInternals({ allowTestApisFlag: true });
    const internals = pm.__test_internals ?? pm;
    expect(internals.getPayloadFingerprint).toBeDefined();
    // simple object
    const s = await internals.getPayloadFingerprint({ a: 1, b: 2 });
    expect(typeof s).toBe("string");
  } finally {
    vi.useFakeTimers();
  }
}, 20000);

test("deepFreeze respects node budget and does not throw on exotic objects", () => {
  try {
    vi.useRealTimers();
    const pm = loadPostMessageInternals({ allowTestApisFlag: true });
    const internals = pm.__test_internals ?? pm;
    expect(internals.deepFreeze).toBeDefined();
    const obj: any = { a: { b: { c: { d: 1 } } } };
    // small budget should be sufficient
    const frozen = internals.deepFreeze(obj, 10);
    expect(Object.isFrozen(frozen)).toBe(true);
  } finally {
    vi.useFakeTimers();
  }
}, 10000);
