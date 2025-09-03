import { test, expect, vi } from "vitest";
import loadPostMessageInternals from "../../tests/helpers/vmPostMessageHelper";

// This test compiles a temporary copy of src/postMessage.ts with a build-time
// macro `__TEST__ = true` so the IIFE that exposes `__test_internals` runs.
// It runs the transpiled code in an isolated VM so we don't mutate the real
// module cache.

test("build-time __TEST__ exposes __test_internals when compiled with macro", async () => {
  // The VM loader executes transpiled code which may rely on real timers and
  // host globals; ensure we are not using fake timers while constructing the VM.
  try {
    vi.useRealTimers();
    // Allow the VM to expose test-only internals regardless of environment guard.
    // This prevents the VM from throwing when development guards check globals/env.
    // Use a host-global token, tests must clean up afterward.
    (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;
    const pm = loadPostMessageInternals();
    expect(pm.__test_internals).toBeDefined();
    const internals = pm.__test_internals;
    expect(typeof internals.toNullProto).toBe("function");
    const res = internals.toNullProto({ a: 1, __proto__: { polluted: true } });
    expect(res).toBeDefined();
  } finally {
    try {
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    } catch {}
    vi.useFakeTimers();
  }
}, 20000);
