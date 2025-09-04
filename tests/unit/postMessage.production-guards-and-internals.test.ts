import { expect, test } from "vitest";

// This test exercises the runtime production guard that blocks test-only APIs
// when environment.isProduction is true and no explicit allow flag is set.

test("production guard blocks test-only APIs when not allowed", async () => {
  // Ensure environment is production for this test invocation
  const env = await import("../../src/environment");

  // Force production before importing the module under test so its guards run
  // under production semantics at module-evaluation time.
  env.environment.setExplicitEnv("production");

  // Ensure process env does not allow test APIs for this test
  const prevEnv = process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (process.env as any).SECURITY_KIT_ALLOW_TEST_APIS = undefined;

  // Ensure the global allow flag is not set
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;

  // Import after switching to production so guarded internals are not exposed
  const pm = await import("../../src/postMessage");

  // __test_internals should be undefined due to runtime guard
  expect(pm.__test_internals).toBeUndefined();

  // Calling a test-only wrapper should throw due to guard
  let threw = false;
  try {
    // __test_toNullProto calls the inline guard
    pm.__test_toNullProto({ a: 1 });
  } catch (e) {
    threw = true;
    expect(String(e)).toMatch(/Test-only APIs are disabled in production/);
  }
  expect(threw).toBe(true);

  // Restore environment to development for other tests
  env.environment.setExplicitEnv("development");
  if (typeof prevEnv === "undefined")
    delete process.env.SECURITY_KIT_ALLOW_TEST_APIS;
  else process.env.SECURITY_KIT_ALLOW_TEST_APIS = prevEnv;
});
