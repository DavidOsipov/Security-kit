import { expect, test } from "vitest";

// This test manipulates global.require to simulate environments where the
// synchronous IIFE in `src/postMessage.ts` cannot load `./development-guards`.
// That branch logs a warning "Test internals not exposed" and returns
// undefined; we assert that the exported __test_internals is undefined in
// that case. This exercises the error-handling around the require() path.

test("IIFE returns undefined when require is unavailable or throws", async () => {
  // Preserve original require if present
  const origReq = (globalThis as any).require;
  try {
    // Provide a require that throws
    (globalThis as any).require = () => {
      throw new Error("simulated require failure");
    };

    // Dynamically import a fresh copy of the module so the IIFE executes now
    const mod = await import("../../src/postMessage");
    // __test_internals should be undefined because the IIFE could not expose
    // internals due to the simulated require failure.
    expect(mod.__test_internals).toBeUndefined();
  } finally {
    // Restore original require
    if (typeof origReq === "undefined") delete (globalThis as any).require;
    else (globalThis as any).require = origReq;
  }
});
