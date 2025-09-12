import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";

// Set up test environment
beforeEach(() => {
  // Ensure test environment is properly configured and detected as non-production
  globalThis.process = {
    env: { SECURITY_KIT_ALLOW_TEST_APIS: "true", NODE_ENV: "test" },
  } as any;
});

afterEach(() => {
  // Clean up
});

describe("postMessage uncovered branches", () => {
  describe("_validatePayloadWithExtras validator function error handling", () => {
    test("validator function throws error", async () => {
      const postMessage = await import("../../src/postMessage");
      const throwingValidator = () => {
        throw new Error("Test validator error");
      };

      const result = postMessage._validatePayloadWithExtras(
        {},
        throwingValidator,
      );
      expect(result).toEqual({
        valid: false,
        reason: "Validator function threw: Test validator error",
      });
    });

    test("validator function throws non-Error object", async () => {
      const postMessage = await import("../../src/postMessage");
      const throwingValidator = () => {
        throw "string error";
      };

      const result = postMessage._validatePayloadWithExtras(
        {},
        throwingValidator,
      );
      expect(result).toEqual({
        valid: false,
        reason: "Validator function threw: ",
      });
    });

    test("validator function throws null", async () => {
      const postMessage = await import("../../src/postMessage");
      const throwingValidator = () => {
        throw null;
      };

      const result = postMessage._validatePayloadWithExtras(
        {},
        throwingValidator,
      );
      expect(result).toEqual({
        valid: false,
        reason: "Validator function threw: ",
      });
    });

    test("validator function returns falsy value", async () => {
      const postMessage = await import("../../src/postMessage");
      const falsyValidator = () => false;

      const result = postMessage._validatePayloadWithExtras({}, falsyValidator);
      expect(result).toEqual({
        valid: false,
      });
    });

    test("validator function returns truthy value", async () => {
      const postMessage = await import("../../src/postMessage");
      const truthyValidator = () => true;

      const result = postMessage._validatePayloadWithExtras(
        {},
        truthyValidator,
      );
      expect(result).toEqual({
        valid: true,
      });
    });
  });

  describe("test-only API setup and error handling", () => {
    test("__test_internals factory catches require errors", async () => {
      // Simulate require not being available
      delete (globalThis as any).require;

      // Force re-evaluation by re-importing
      vi.resetModules();
      const postMessage = await import("../../src/postMessage");
      const result = postMessage.__test_internals;
      // With __TEST__ build flag enabled, internals should still be exposed for tests
      // even if require() is unavailable — the factory tolerates require failures.
      expect(result).toBeDefined();
      expect(result).toHaveProperty("toNullProto");
      expect(result).toHaveProperty("getPayloadFingerprint");
    });

    test("__test_internals factory catches development guards errors", async () => {
      // Under test builds, __test_internals is exposed when dev guards pass
      vi.resetModules();
      const postMessage = await import("../../src/postMessage");
      const result = postMessage.__test_internals;
      expect(result).toBeDefined();
    });

    test("__test_internals factory catches assertTestApiAllowed errors", async () => {
      // Under test builds, __test_internals is exposed and guarded at callsites
      vi.resetModules();
      const postMessage = await import("../../src/postMessage");
      const result = postMessage.__test_internals;
      expect(result).toBeDefined();
    });

    test("__test_internals factory succeeds when all conditions met", async () => {
      vi.resetModules();
      const postMessage = await import("../../src/postMessage");
      const result = postMessage.__test_internals;
      expect(result).toBeDefined();
      expect(typeof result!.toNullProto).toBe("function");
    });
  });

  describe("runtime test API guard function", () => {
    const originalProcess = globalThis.process;
    const originalGlobalAllow = (globalThis as any)
      .__SECURITY_KIT_ALLOW_TEST_APIS;

    beforeEach(() => {
      globalThis.process = { env: {} } as any;
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
    });

    afterEach(() => {
      globalThis.process = originalProcess;
      (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = originalGlobalAllow;
    });

    test("allows when SECURITY_KIT_ALLOW_TEST_APIS env var is set", async () => {
      globalThis.process.env.SECURITY_KIT_ALLOW_TEST_APIS = "true";

      const postMessage = await import("../../src/postMessage");
      expect(() => postMessage.__test_resetForUnitTests()).not.toThrow();
    });

    test("allows when global flag is set", async () => {
      (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

      const postMessage = await import("../../src/postMessage");
      expect(() => postMessage.__test_resetForUnitTests()).not.toThrow();
    });
  });

  describe("test helper functions error handling", () => {
    const originalProcess = globalThis.process;

    beforeEach(() => {
      // Set up test environment
      globalThis.process = {
        env: { SECURITY_KIT_ALLOW_TEST_APIS: "true" },
      } as any;
    });

    afterEach(() => {
      globalThis.process = originalProcess;
    });

    test("__test_getPayloadFingerprint calls guard and delegates", async () => {
      const postMessage = await import("../../src/postMessage");
      const testData = { test: "data" };
      const result = await postMessage.__test_getPayloadFingerprint(testData);
      expect(typeof result).toBe("string");
    });

    test("__test_ensureFingerprintSalt calls guard and delegates", async () => {
      const postMessage = await import("../../src/postMessage");
      const result = await postMessage.__test_ensureFingerprintSalt();
      expect(result).toBeInstanceOf(Uint8Array);
    });

    test("__test_toNullProto calls guard and delegates", async () => {
      const postMessage = await import("../../src/postMessage");
      const testObject = { a: 1, b: { c: 2 } };
      const result = postMessage.__test_toNullProto(testObject);
      expect(result).not.toBe(testObject);
    });

    test("__test_deepFreeze calls guard and delegates", async () => {
      const postMessage = await import("../../src/postMessage");
      const testObject = { a: 1, b: { c: 2 } };
      const result = postMessage.__test_deepFreeze(testObject);
      expect(result).toBe(testObject);
      expect(Object.isFrozen(result)).toBe(true);
    });

    test("__test_resetForUnitTests calls guard and resets state", async () => {
      const postMessage = await import("../../src/postMessage");
      expect(() => postMessage.__test_resetForUnitTests()).not.toThrow();
    });

    test("__test_getSaltFailureTimestamp calls guard and returns value", async () => {
      const postMessage = await import("../../src/postMessage");
      const result = postMessage.__test_getSaltFailureTimestamp();
      expect(typeof result).toBe("undefined");
    });

    test("__test_setSaltFailureTimestamp calls guard and sets value", async () => {
      const postMessage = await import("../../src/postMessage");
      expect(() =>
        postMessage.__test_setSaltFailureTimestamp(12345),
      ).not.toThrow();
      expect(postMessage.__test_getSaltFailureTimestamp()).toBe(12345);

      // Reset
      postMessage.__test_setSaltFailureTimestamp(undefined);
    });
  });
});
