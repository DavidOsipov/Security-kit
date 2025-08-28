import { expect, test } from "vitest";

test("_assertTestApiAllowedInline returns when environment accessor throws", async () => {
  // Import environment and the test-only API
  const envModule = await import("../../src/environment");
  const pm = await import("../../src/postMessage");

  const originalDesc = Object.getOwnPropertyDescriptor(
    envModule.environment,
    "isProduction",
  );

  // Force the getter to throw to hit the catch branch inside _assertTestApiAllowedInline
  Object.defineProperty(envModule.environment, "isProduction", {
    configurable: true,
    get() {
      throw new Error("boom");
    },
  });

  try {
    // Call a synchronous test API that is guarded; the guard will catch and return
    const out = pm.__test_toNullProto({ a: 1 });
    expect(out).toEqual({ a: 1 });
  } finally {
    // Restore original descriptor
    if (originalDesc) {
      Object.defineProperty(envModule.environment, "isProduction", originalDesc);
    }
  }
});
