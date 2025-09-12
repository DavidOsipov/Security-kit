import { expect, test, vi } from "vitest";

// This test manipulates global.require to simulate environments where the
// synchronous IIFE in `src/postMessage.ts` cannot load `./development-guards`.
// That branch logs a warning "Test internals not exposed" and returns
// undefined; we assert that the exported __test_internals is undefined in
// that case. This exercises the error-handling around the require() path.

test("IIFE returns undefined when require is unavailable or throws", async () => {
  // Preserve original require if present
  const origReq = (globalThis as any).require;
  const origAllow = (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
  const origEnvAllow = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  try {
    // Provide a require that throws
    (globalThis as any).require = () => {
      throw new Error("simulated require failure");
    };
    // Ensure global allow flag is not set for this negative test
    delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    // Ensure env allow flag is not set for this negative test
    delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;

    // Force fresh evaluation so the IIFE runs under the simulated failure
    vi.resetModules();

    // Dynamically import a fresh copy of the module so the IIFE executes now
    const mod = await import("../../src/postMessage");
    // __test_internals should be undefined because the IIFE could not expose
    // internals due to the simulated require failure.
    expect(mod.__test_internals).toBeUndefined();
  } finally {
    // Restore original require
    if (typeof origReq === "undefined") delete (globalThis as any).require;
    else (globalThis as any).require = origReq;
    // Restore global allow flag
    if (typeof origAllow === "undefined")
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    else (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = origAllow;
    // Restore env allow flag
    if (typeof origEnvAllow === "undefined")
      delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
    else process.env.SECURITY_KIT_ALLOW_TEST_APIS = origEnvAllow;
  }
});
