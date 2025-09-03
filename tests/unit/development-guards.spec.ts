import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { assertTestApiAllowed } from "../../src/development-guards.js";
import { InvalidConfigurationError } from "../../src/errors.js";
import { environment } from "../../src/environment.js";

describe("development-guards", () => {
  describe("assertTestApiAllowed", () => {
    let originalProcess: typeof process | undefined;
    let originalIsProduction: boolean;

    beforeEach(() => {
      originalProcess = global.process;
      originalIsProduction = environment.isProduction;
    });

    afterEach(() => {
      if (originalProcess !== undefined) {
        global.process = originalProcess;
      }
      // Restore any global flags we might have set
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;
      // Reset environment
      environment.setExplicitEnv(originalIsProduction ? "production" : "development");
    });

    it("does not throw when not in production", () => {
      // Ensure we're in development mode
      environment.setExplicitEnv("development");
      expect(() => assertTestApiAllowed()).not.toThrow();
    });

    it("does not throw when in production with SECURITY_KIT_ALLOW_TEST_APIS=true", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Mock process.env to allow test APIs
      global.process = {
        ...originalProcess,
        env: {
          ...originalProcess?.env,
          SECURITY_KIT_ALLOW_TEST_APIS: "true",
        },
      } as any;

      expect(() => assertTestApiAllowed()).not.toThrow();
    });

    it("does not throw when in production with global flag set", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Set global flag
      (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

      expect(() => assertTestApiAllowed()).not.toThrow();
    });

    it("throws InvalidConfigurationError when in production without any allow flags", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Ensure no env var
      global.process = {
        ...originalProcess,
        env: {
          ...originalProcess?.env,
          SECURITY_KIT_ALLOW_TEST_APIS: undefined,
        },
      } as any;

      // Ensure no global flag
      delete (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS;

      expect(() => assertTestApiAllowed()).toThrow(InvalidConfigurationError);
      expect(() => assertTestApiAllowed()).toThrow(
        "Test-only APIs are disabled in production. Set SECURITY_KIT_ALLOW_TEST_APIS=true or set globalThis.__SECURITY_KIT_ALLOW_TEST_APIS = true to explicitly allow.",
      );
    });

    it("throws InvalidConfigurationError when in production with env var set to false", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Set env var to false
      global.process = {
        ...originalProcess,
        env: {
          ...originalProcess?.env,
          SECURITY_KIT_ALLOW_TEST_APIS: "false",
        },
      } as any;

      expect(() => assertTestApiAllowed()).toThrow(InvalidConfigurationError);
    });

    it("throws InvalidConfigurationError when in production with global flag set to false", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Ensure no env var - set it explicitly to undefined
      global.process = {
        ...originalProcess,
        env: {
          ...originalProcess?.env,
        },
      } as any;
      delete global.process.env.SECURITY_KIT_ALLOW_TEST_APIS;

      // Set global flag to false
      (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = false;

      expect(() => assertTestApiAllowed()).toThrow(InvalidConfigurationError);
    });

    it("does not throw when process is undefined but global flag is set", () => {
      // Set to production mode
      environment.setExplicitEnv("production");

      // Mock process as undefined
      global.process = undefined as any;

      // Set global flag
      (globalThis as any).__SECURITY_KIT_ALLOW_TEST_APIS = true;

      expect(() => assertTestApiAllowed()).not.toThrow();
    });
  });
});