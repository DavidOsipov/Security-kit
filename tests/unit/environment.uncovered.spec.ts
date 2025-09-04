import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { environment, isDevelopment } from "../../src/environment";

const savedLocation = (globalThis as any).location;
const savedEnv = process.env.NODE_ENV;
const savedProcess = globalThis.process;

beforeEach(() => {
  environment.clearCache();
  delete (globalThis as any).location;
  process.env.NODE_ENV = savedEnv;
  // Reset explicit environment
  environment.setExplicitEnv("development");
  environment.clearCache();
});

afterEach(() => {
  environment.clearCache();
  (globalThis as any).location = savedLocation;
  process.env.NODE_ENV = savedEnv;
  globalThis.process = savedProcess;
});

describe("environment utils - uncovered branches", () => {
  describe("isPrivate172 function edge cases", () => {
    it("handles non-string hostname input", () => {
      // Test with undefined, null, number, object
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: undefined };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);

      (globalThis as any).location = { hostname: null };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);

      (globalThis as any).location = { hostname: 123 };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);

      (globalThis as any).location = { hostname: {} };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);
    });

    it("handles malformed IP addresses", () => {
      delete process.env.NODE_ENV;
      const malformedHosts = [
        "172.16", // too few parts
        "172.16.1.1.1", // too many parts
        "172.16.abc.1", // non-numeric parts
        "172.16.1.", // trailing dot
        ".172.16.1.1", // leading dot
        " 172.16.1.1 ", // whitespace
      ];

      for (const host of malformedHosts) {
        (globalThis as any).location = { hostname: host };
        environment.clearCache();
        expect(environment.isDevelopment, `host: "${host}"`).toBe(false);
      }
    });

    it("handles edge cases in 172 range", () => {
      delete process.env.NODE_ENV;
      // Test boundaries
      (globalThis as any).location = { hostname: "172.15.255.255" }; // just below 16
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);

      (globalThis as any).location = { hostname: "172.16.0.0" }; // exactly 16
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true);

      (globalThis as any).location = { hostname: "172.31.255.255" }; // exactly 31
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true);

      (globalThis as any).location = { hostname: "172.32.0.0" }; // just above 31
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);
    });
  });

  describe("isDevelopment getter edge cases", () => {
    it("handles missing location object", () => {
      delete process.env.NODE_ENV;
      delete (globalThis as any).location;
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);
    });

    it("handles location without hostname property", () => {
      delete process.env.NODE_ENV;
      (globalThis as any).location = {};
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);
    });

    it("handles empty hostname", () => {
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true); // empty hostname is in developmentHostnames
    });

    it("handles undefined process in browser environment", () => {
      delete process.env.NODE_ENV;
      const originalProcess = globalThis.process;
      delete (globalThis as any).process;

      try {
        (globalThis as any).location = { hostname: "example.com" };
        environment.clearCache();
        expect(environment.isDevelopment).toBe(false);
      } finally {
        globalThis.process = originalProcess;
      }
    });

    it("handles error in location access", () => {
      delete process.env.NODE_ENV;
      // Mock location getter to throw
      const originalLocation = Object.getOwnPropertyDescriptor(
        globalThis,
        "location",
      );
      Object.defineProperty(globalThis, "location", {
        get: () => {
          throw new Error("Access denied");
        },
        configurable: true,
      });

      try {
        environment.clearCache();
        expect(environment.isDevelopment).toBe(false);
      } finally {
        if (originalLocation) {
          Object.defineProperty(globalThis, "location", originalLocation);
        } else {
          delete (globalThis as any).location;
        }
      }
    });

    it("caches results correctly with explicit environment", () => {
      // Set explicit environment
      environment.setExplicitEnv("production");

      // First call should compute and cache
      expect(environment.isDevelopment).toBe(false);

      // Second call should use cache
      expect(environment.isDevelopment).toBe(false);

      // Change explicit environment should clear cache
      environment.setExplicitEnv("development");
      expect(environment.isDevelopment).toBe(true);
    });

    it("caches results correctly with NODE_ENV", () => {
      process.env.NODE_ENV = "development";

      // First call should compute and cache
      expect(environment.isDevelopment).toBe(true);

      // Second call should use cache
      expect(environment.isDevelopment).toBe(true);

      // Clear cache should recompute
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true);
    });

    it("caches results correctly with hostname detection", () => {
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "localhost" };

      // First call should compute and cache
      expect(environment.isDevelopment).toBe(true);

      // Second call should use cache
      expect(environment.isDevelopment).toBe(true);

      // Clear cache should recompute
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true);
    });
  });

  describe("isProduction getter", () => {
    it("returns true when explicit environment is production", () => {
      environment.setExplicitEnv("production");
      expect(environment.isProduction).toBe(true);
    });

    it("returns false when explicit environment is development", () => {
      environment.setExplicitEnv("development");
      expect(environment.isProduction).toBe(false);
    });

    it("negates isDevelopment when no explicit environment", () => {
      environment.clearCache();
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "localhost" };
      environment.clearCache();

      const devResult = environment.isDevelopment;
      const prodResult = environment.isProduction;
      expect(prodResult).toBe(!devResult);
    });
  });

  describe("setExplicitEnv and clearCache interaction", () => {
    it("setExplicitEnv clears cache immediately", () => {
      // Set up initial state
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "example.com" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false);

      // Set explicit environment - should clear cache
      environment.setExplicitEnv("development");
      expect(environment.isDevelopment).toBe(true);

      // Verify cache was cleared by changing location but keeping explicit env
      (globalThis as any).location = { hostname: "localhost" };
      expect(environment.isDevelopment).toBe(true); // should still be true due to explicit env
    });

    it("clearCache resets explicit environment behavior", () => {
      environment.setExplicitEnv("production");
      expect(environment.isDevelopment).toBe(false);

      environment.clearCache();
      // After clearing cache, should fall back to detection
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "localhost" };
      expect(environment.isDevelopment).toBe(true);
    });
  });

  describe("hostname detection edge cases", () => {
    it("handles case insensitive hostname matching", () => {
      delete process.env.NODE_ENV;
      const testCases = [
        { hostname: "LOCALHOST", expected: true },
        { hostname: "Localhost", expected: true },
        { hostname: "EXAMPLE.TEST", expected: true },
        { hostname: "example.TEST", expected: true },
        { hostname: "192.168.1.1", expected: true },
        { hostname: "192.168.1.1".toUpperCase(), expected: true },
      ];

      for (const { hostname, expected } of testCases) {
        (globalThis as any).location = { hostname };
        environment.clearCache();
        expect(environment.isDevelopment, `hostname: ${hostname}`).toBe(
          expected,
        );
      }
    });

    it("handles hostname with port numbers", () => {
      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "localhost:3000" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false); // localhost:3000 doesn't match exact localhost

      (globalThis as any).location = { hostname: "127.0.0.1:8080" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false); // 127.0.0.1:8080 doesn't match exact 127.0.0.1
    });

    it("handles internationalized domain names", () => {
      delete process.env.NODE_ENV;
      // Test with unicode characters
      (globalThis as any).location = { hostname: "test.本地" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false); // Should not match .local suffix

      (globalThis as any).location = { hostname: "test.local" };
      environment.clearCache();
      expect(environment.isDevelopment).toBe(true);
    });
  });

  describe("NODE_ENV edge cases", () => {
    it("handles empty NODE_ENV", () => {
      process.env.NODE_ENV = "";
      environment.clearCache();
      expect(environment.isDevelopment).toBe(false); // empty string is not development or test
    });

    it("handles undefined NODE_ENV", () => {
      delete process.env.NODE_ENV;
      environment.clearCache();
      // Should fall back to hostname detection
      (globalThis as any).location = { hostname: "localhost" };
      expect(environment.isDevelopment).toBe(true);
    });

    it("handles case variations in NODE_ENV", () => {
      const testCases = [
        { env: "DEVELOPMENT", expected: true },
        { env: "Development", expected: true },
        { env: "TEST", expected: true },
        { env: "Test", expected: true },
        { env: "PRODUCTION", expected: false },
        { env: "Production", expected: false },
        { env: "staging", expected: false },
      ];

      for (const { env, expected } of testCases) {
        process.env.NODE_ENV = env;
        environment.clearCache();
        expect(environment.isDevelopment, `NODE_ENV: ${env}`).toBe(expected);
      }
    });

    it("ensures NODE_ENV path cache is set correctly", () => {
      // Test that the cache.set line for NODE_ENV is executed
      process.env.NODE_ENV = "development";
      environment.clearCache();

      // First call should execute NODE_ENV logic and set cache
      expect(environment.isDevelopment).toBe(true);

      // Second call should use cache
      expect(environment.isDevelopment).toBe(true);
    });
  });

  describe("exported isDevelopment function", () => {
    it("returns the same value as environment.isDevelopment", async () => {
      // Test the exported function
      const { isDevelopment: exportedIsDevelopment } = await import(
        "../../src/environment"
      );

      // Test with different scenarios
      process.env.NODE_ENV = "development";
      environment.clearCache();
      expect(exportedIsDevelopment()).toBe(environment.isDevelopment);

      process.env.NODE_ENV = "production";
      environment.clearCache();
      expect(exportedIsDevelopment()).toBe(environment.isDevelopment);

      delete process.env.NODE_ENV;
      (globalThis as any).location = { hostname: "localhost" };
      environment.clearCache();
      expect(exportedIsDevelopment()).toBe(environment.isDevelopment);
    });
  });

  describe("isPrivate172 function return statement coverage", () => {
    it("ensures return statement is executed for valid 172 range", () => {
      delete process.env.NODE_ENV;
      // Test cases that should hit the return statement on line 32
      const valid172Hosts = ["172.16.0.0", "172.20.0.0", "172.31.255.255"];

      for (const host of valid172Hosts) {
        (globalThis as any).location = { hostname: host };
        environment.clearCache();
        expect(environment.isDevelopment).toBe(true);
      }
    });

    it("ensures return statement is executed for invalid 172 range", () => {
      delete process.env.NODE_ENV;
      // Test cases that should hit the return statement but return false
      const invalid172Hosts = [
        "172.15.255.255", // below 16
        "172.32.0.0", // above 31
      ];

      for (const host of invalid172Hosts) {
        (globalThis as any).location = { hostname: host };
        environment.clearCache();
        expect(environment.isDevelopment).toBe(false);
      }
    });
  });
});
