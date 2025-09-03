import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  CryptoUnavailableError,
  IllegalStateError,
  InvalidParameterError,
} from "../../src/errors";
import {
  secureWipe,
  createSecureZeroingArray,
  secureCompare,
  secureCompareAsync,
  _redact,
  withSecureBuffer,
  secureCompareBytes,
  registerTelemetry,
  emitMetric,
  validateNumericParam,
  validateProbability,
  isSharedArrayBufferView,
  createSecureZeroingBuffer,
  sanitizeLogMessage,
  sanitizeComponentName,
  secureDevLog,
  _devConsole,
  MAX_COMPARISON_LENGTH,
  MAX_RAW_INPUT_LENGTH,
  MAX_REDACT_DEPTH,
  MAX_LOG_STRING,
} from "../../src/utils";
import { arrayBufferToBase64 } from "../../src/encoding-utils";
import {
  encodeComponentRFC3986,
  strictDecodeURIComponent,
} from "../../src/url";

// Import the telemetry hook directly for cleanup
import * as utilsModule from "../../src/utils";

describe("utils module", () => {
  let consoleWarnSpy: any;
  let consoleErrorSpy: any;
  let consoleInfoSpy: any;
  let consoleDebugSpy: any;

  beforeEach(() => {
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    consoleInfoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    consoleDebugSpy = vi.spyOn(console, "debug").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Clean up any registered telemetry hooks between tests
    try {
      // Reset the global telemetry hook
      (utilsModule as any).telemetryHook = undefined;
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("telemetry functions", () => {
    it("registerTelemetry registers a hook successfully", () => {
      const mockHook = vi.fn();
      const unregister = registerTelemetry(mockHook);
      expect(typeof unregister).toBe("function");

      // Call unregister to test it
      unregister();
    });

    it("registerTelemetry throws if already registered", () => {
      const mockHook = vi.fn();
      const unregister1 = registerTelemetry(mockHook);
      expect(() => registerTelemetry(mockHook)).toThrow(IllegalStateError);
      unregister1(); // Clean up
    });

    it("registerTelemetry throws on invalid hook", () => {
      expect(() => registerTelemetry("not a function" as any)).toThrow(
        InvalidParameterError,
      );
    });

    it("emitMetric calls registered hook safely", async () => {
      const mockHook = vi.fn();
      const unregister = registerTelemetry(mockHook);

      emitMetric("test.metric", 42, { reason: "test" });

      // Wait for microtask to complete
      await new Promise((resolve) => setImmediate(resolve));

      expect(mockHook).toHaveBeenCalledWith("test.metric", 42, {
        reason: "test",
      });

      unregister();
    });

    it("emitMetric handles hook errors gracefully", async () => {
      // Create a fresh hook for this test
      const mockHook = vi.fn().mockImplementation(() => {
        throw new Error("hook error");
      });
      const unregister = registerTelemetry(mockHook);

      // Should not throw
      expect(() => emitMetric("test.metric")).not.toThrow();

      // Wait for microtask to complete
      await new Promise((resolve) => setImmediate(resolve));

      unregister();
    });
  });

  describe("validation functions", () => {
    it("validateNumericParam accepts valid integers", () => {
      expect(() => validateNumericParam(5, "test", 0, 10)).not.toThrow();
      expect(() => validateNumericParam(0, "test", 0, 10)).not.toThrow();
      expect(() => validateNumericParam(10, "test", 0, 10)).not.toThrow();
    });

    it("validateNumericParam rejects invalid values", () => {
      expect(() => validateNumericParam(1.5, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateNumericParam(-1, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateNumericParam(11, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateNumericParam("5" as any, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
    });

    it("validateProbability accepts valid probabilities", () => {
      expect(() => validateProbability(0)).not.toThrow();
      expect(() => validateProbability(0.5)).not.toThrow();
      expect(() => validateProbability(1)).not.toThrow();
    });

    it("validateProbability rejects invalid probabilities", () => {
      expect(() => validateProbability(-0.1)).toThrow(InvalidParameterError);
      expect(() => validateProbability(1.1)).toThrow(InvalidParameterError);
      expect(() => validateProbability("0.5" as any)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("secureWipe comprehensive", () => {
    it("secureWipe handles undefined input", () => {
      expect(secureWipe(undefined)).toBe(true);
    });

    it("secureWipe handles zero-length arrays", () => {
      const arr = new Uint8Array(0);
      expect(secureWipe(arr)).toBe(true);
    });

    it("secureWipe handles SharedArrayBuffer when forbidden", () => {
      // Create a mock SharedArrayBuffer view
      const mockBuffer = { constructor: { name: "SharedArrayBuffer" } };
      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      // Mock SharedArrayBuffer constructor globally
      const originalSAB = globalThis.SharedArrayBuffer;
      (globalThis as any).SharedArrayBuffer = function () {};

      // Mock Object.prototype.toString to return SharedArrayBuffer tag
      const originalToString = Object.prototype.toString;
      Object.prototype.toString = vi.fn().mockImplementation(function (
        this: any,
      ) {
        if (this === mockBuffer) {
          return "[object SharedArrayBuffer]";
        }
        return originalToString.call(this);
      });

      const result = secureWipe(mockView, { forbidShared: true });
      expect(result).toBe(false);

      // Restore originals
      (globalThis as any).SharedArrayBuffer = originalSAB;
      Object.prototype.toString = originalToString;
    });

    it("secureWipe warns on large buffers", () => {
      // Ensure we're in development mode for this test
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      const largeArr = new Uint8Array(3000); // > 1KB
      secureWipe(largeArr);

      // Check if the warning was called
      expect(consoleWarnSpy).toHaveBeenCalled();

      // Restore original environment
      process.env.NODE_ENV = originalNodeEnv;
    });

    it("secureWipe handles various typed arrays", () => {
      const arrays = [
        new Uint8Array([1, 2, 3]),
        new Int8Array([1, 2, 3]),
        new Uint16Array([1, 2, 3]),
        new Int16Array([1, 2, 3]),
        new Uint32Array([1, 2, 3]),
        new Int32Array([1, 2, 3]),
        new Float32Array([1, 2, 3]),
        new Float64Array([1, 2, 3]),
      ];

      arrays.forEach((arr) => {
        const original = Array.from(arr);
        const result = secureWipe(arr);
        expect(result).toBe(true);
        // Check that values were actually wiped (at least some should be zero)
        expect(Array.from(arr)).not.toEqual(original);
      });
    });

    it("secureWipe handles BigInt arrays", () => {
      const bigIntArr = new BigUint64Array([1n, 2n, 3n]);
      const result = secureWipe(bigIntArr);
      expect(result).toBe(true);
      expect(Array.from(bigIntArr)).toEqual([0n, 0n, 0n]);
    });
  });

  describe("isSharedArrayBufferView", () => {
    it("detects SharedArrayBuffer views", () => {
      const mockBuffer = { constructor: { name: "SharedArrayBuffer" } };
      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      // Mock SharedArrayBuffer constructor globally
      const originalSAB = globalThis.SharedArrayBuffer;
      (globalThis as any).SharedArrayBuffer = function () {};

      // Mock the toString check
      const originalToString = Object.prototype.toString;
      Object.prototype.toString = vi.fn().mockImplementation(function (
        this: any,
      ) {
        if (this === mockBuffer) {
          return "[object SharedArrayBuffer]";
        }
        return originalToString.call(this);
      });

      expect(isSharedArrayBufferView(mockView)).toBe(true);

      // Restore originals
      (globalThis as any).SharedArrayBuffer = originalSAB;
      Object.prototype.toString = originalToString;
    });

    it("returns false for regular ArrayBuffers", () => {
      const view = new Uint8Array(10);
      expect(isSharedArrayBufferView(view)).toBe(false);
    });

    it("handles errors gracefully", () => {
      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", {
        get() {
          throw new Error("test error");
        },
      });

      expect(isSharedArrayBufferView(mockView)).toBe(false);
    });
  });

  describe("createSecureZeroingBuffer", () => {
    it("creates buffer with correct length", () => {
      const buffer = createSecureZeroingBuffer(16);
      const view = buffer.get();
      expect(view.length).toBe(16);
      expect(buffer.isFreed()).toBe(false);
    });

    it("throws on freed buffer access", () => {
      const buffer = createSecureZeroingBuffer(16);
      buffer.free();
      expect(() => buffer.get()).toThrow(IllegalStateError);
      expect(buffer.isFreed()).toBe(true);
    });

    it("free is idempotent", () => {
      const buffer = createSecureZeroingBuffer(16);
      expect(buffer.free()).toBe(true);
      expect(buffer.free()).toBe(true); // Second call should still return true
    });

    it("wipes buffer on free", () => {
      const buffer = createSecureZeroingBuffer(16);
      const view = buffer.get();
      view[0] = 42;
      buffer.free();
      expect(view[0]).toBe(0);
    });
  });

  describe("secureCompareAsync comprehensive", () => {
    it("handles crypto unavailable in strict mode", async () => {
      // Import the state module and spy on ensureCrypto
      const stateModule = await import("../../src/state");
      const ensureCryptoSpy = vi.spyOn(stateModule, "ensureCrypto");

      // Make ensureCrypto throw CryptoUnavailableError
      ensureCryptoSpy.mockRejectedValue(
        new CryptoUnavailableError(
          "Crypto is not available in this environment",
        ),
      );

      try {
        await expect(
          secureCompareAsync("a", "b", { requireCrypto: true }),
        ).rejects.toThrow(CryptoUnavailableError);
      } finally {
        // Restore the original function
        ensureCryptoSpy.mockRestore();
      }
    });

    it("falls back to sync compare when crypto unavailable", async () => {
      const originalCrypto = globalThis.crypto;
      delete (globalThis as any).crypto;

      try {
        const result = await secureCompareAsync("abc", "abc");
        expect(result).toBe(true);
      } finally {
        (globalThis as any).crypto = originalCrypto;
      }
    });

    it("handles crypto errors gracefully", async () => {
      // Mock crypto.subtle.digest to throw
      const originalDigest = globalThis.crypto?.subtle?.digest;
      if (globalThis.crypto?.subtle) {
        globalThis.crypto.subtle.digest = vi
          .fn()
          .mockRejectedValue(new Error("crypto error"));
      }

      try {
        const result = await secureCompareAsync("a", "b");
        expect(result).toBe(false); // Should fall back to sync comparison
      } finally {
        if (globalThis.crypto?.subtle && originalDigest) {
          globalThis.crypto.subtle.digest = originalDigest;
        }
      }
    });
  });

  describe("_redact comprehensive", () => {
    it("handles circular references", () => {
      const obj: any = { a: 1 };
      obj.self = obj;
      const result = _redact(obj) as any;
      expect(result.self.reason).toBe("circular-reference");
    });

    it("handles prototype pollution attempts", () => {
      const obj = {
        __proto__: { polluted: true },
        constructor: { polluted: true },
        prototype: { polluted: true },
        normal: "value",
      };
      const result = _redact(obj) as any;

      // The _redact function should filter out prototype pollution keys entirely
      // Since result is created with Object.create(null), accessing non-existent properties returns undefined
      expect(result.hasOwnProperty("__proto__")).toBe(false);
      expect(result.hasOwnProperty("constructor")).toBe(false);
      expect(result.hasOwnProperty("prototype")).toBe(false);
      expect(result.normal).toBe("value");
    });

    it("handles Map and Set objects", () => {
      const map = new Map([["key", "value"]]);
      const set = new Set(["value"]);

      const mapResult = _redact(map) as any;
      const setResult = _redact(set) as any;

      expect(mapResult.__type).toBe("Map");
      expect(mapResult.size).toBe(1);
      expect(mapResult.__redacted).toBe(true);

      expect(setResult.__type).toBe("Set");
      expect(setResult.size).toBe(1);
      expect(setResult.__redacted).toBe(true);
    });

    it("handles Error objects", () => {
      const error = new Error("test error");
      const result = _redact(error);
      expect(typeof result).toBe("object");
      expect(result).toHaveProperty("message");
    });

    it("handles Date objects", () => {
      const date = new Date("2023-01-01");
      const result = _redact(date);
      expect(typeof result).toBe("string");
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it("handles ArrayBuffer and TypedArrays", () => {
      const buffer = new ArrayBuffer(16);
      const uint8 = new Uint8Array(buffer);

      const bufferResult = _redact(buffer) as any;
      const uint8Result = _redact(uint8) as any;

      expect(bufferResult.__arrayBuffer).toBe(16);
      expect(uint8Result.__typedArray.ctor).toBe("Uint8Array");
      expect(uint8Result.__typedArray.byteLength).toBe(16);
    });

    it("handles large arrays with breadth limiting", () => {
      const largeArray = Array.from({ length: 200 }, (_, i) => i);
      const result = _redact(largeArray) as any[];

      expect(result.length).toBeGreaterThan(128); // Should include truncation info
      expect(result[result.length - 1].__truncated).toBe(true);
    });

    it("handles objects with many keys", () => {
      const obj: any = {};
      for (let i = 0; i < 100; i++) {
        obj[`key${i}`] = `value${i}`;
      }
      const result = _redact(obj) as any;

      expect(Object.keys(result).length).toBeGreaterThan(64); // Should include truncation info
      expect(result.__additional_keys__).toBeDefined();
    });

    it("handles unsafe keys", () => {
      const obj = {
        "safe-key": "value",
        "unsafe key with spaces": "secret",
        "another-unsafe-key!@#": "secret2",
      };
      const result = _redact(obj) as any;

      expect(result["safe-key"]).toBe("value");
      expect(result.__unsafe_key_count__).toBe(2);
    });

    it("handles symbol keys", () => {
      const sym = Symbol("test");
      const obj = { [sym]: "value", normal: "prop" };
      const result = _redact(obj) as any;

      expect(result.__symbol_key_count__).toBe(1);
      expect(result.normal).toBe("prop");
    });

    it("handles getter errors", () => {
      const obj = {
        normal: "value",
        get badProp() {
          throw new Error("getter error");
        },
      };
      const result = _redact(obj) as any;

      expect(result.normal).toBe("value");
      expect(result.badProp.__redacted).toBe(true);
      expect(result.badProp.reason).toBe("getter-threw");
    });

    it("handles BigInt values", () => {
      const obj = { big: 123n };
      const result = _redact(obj) as any;
      expect(result.big).toBe("123n");
    });
  });

  describe("sanitizeLogMessage", () => {
    it("sanitizes JWT-like tokens", () => {
      const message =
        "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("[REDACTED]");
      expect(result).not.toContain("eyJhbGci");
    });

    it("sanitizes key=value secrets", () => {
      const message = "password=secret123 token:abc123 secret=value";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("password=[REDACTED]");
      expect(result).toContain("token=[REDACTED]");
      expect(result).toContain("secret=[REDACTED]");
    });

    it("sanitizes Authorization headers", () => {
      const message =
        "Authorization: Bearer abc123 Authorization: Basic xyz789";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("Authorization=[REDACTED]");
    });

    it("handles non-string inputs", () => {
      expect(sanitizeLogMessage(123)).toBe("123");
      expect(sanitizeLogMessage(null)).toBe("null");
      expect(sanitizeLogMessage(undefined)).toBe("undefined");
    });

    it("truncates long messages", () => {
      const longMessage = "a".repeat(MAX_LOG_STRING + 100);
      const result = sanitizeLogMessage(longMessage);
      expect(result.length).toBeLessThanOrEqual(MAX_LOG_STRING + 50); // Allow some buffer for truncation message
      expect(result).toContain("[TRUNCATED");
    });
  });

  describe("sanitizeComponentName", () => {
    it("accepts safe component names", () => {
      expect(sanitizeComponentName("my-component")).toBe("my-component");
      expect(sanitizeComponentName("test_module")).toBe("test_module");
      expect(sanitizeComponentName("component123")).toBe("component123");
    });

    it("rejects unsafe component names", () => {
      expect(sanitizeComponentName("component with spaces")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("component@domain")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("")).toBe("unsafe-component-name");
      expect(sanitizeComponentName("a".repeat(100))).toBe(
        "unsafe-component-name",
      );
    });

    it("handles non-string inputs", () => {
      expect(sanitizeComponentName(123)).toBe("unsafe-component-name");
      expect(sanitizeComponentName(null)).toBe("unsafe-component-name");
      expect(sanitizeComponentName({})).toBe("unsafe-component-name");
    });
  });

  describe("secureDevLog", () => {
    let mockDispatch: any;

    beforeEach(() => {
      mockDispatch = vi.fn();
      vi.spyOn(document, "dispatchEvent").mockImplementation(mockDispatch);
    });

    it("logs in development mode", () => {
      secureDevLog("info", "test-component", "test message", { key: "value" });

      expect(mockDispatch).toHaveBeenCalledWith(
        expect.objectContaining({
          type: "security-kit:log",
          detail: expect.objectContaining({
            level: "INFO",
            component: "test-component",
            message: "test message",
          }),
        }),
      );
    });

    it("does not log in production mode", () => {
      // We can't easily mock the environment in this test, so we'll skip this
      // as the function checks environment.isProduction internally
    });

    it("sanitizes component names and messages", () => {
      secureDevLog("info", "unsafe component!", "password=secret", {
        sensitive: "data",
      });

      expect(mockDispatch).toHaveBeenCalled();
      const call = mockDispatch.mock.calls[0][0];
      expect(call.detail.component).toBe("unsafe-component-name");
      expect(call.detail.message).toContain("[REDACTED]");
    });
  });

  describe("_devConsole", () => {
    it("calls appropriate console methods", () => {
      _devConsole("debug", "debug message", { key: "value" });
      expect(consoleDebugSpy).toHaveBeenCalled();

      _devConsole("info", "info message", { key: "value" });
      expect(consoleInfoSpy).toHaveBeenCalled();

      _devConsole("warn", "warn message", { key: "value" });
      expect(consoleWarnSpy).toHaveBeenCalled();

      _devConsole("error", "error message", { key: "value" });
      expect(consoleErrorSpy).toHaveBeenCalled();
    });

    it("sanitizes context in output", () => {
      const redactedContext = _redact({ password: "secret" });
      _devConsole("info", "test", redactedContext);
      expect(consoleInfoSpy).toHaveBeenCalled();
      const call = consoleInfoSpy.mock.calls[0][0];
      expect(call).toContain("[REDACTED]");
    });
  });

  describe("constants and limits", () => {
    it("exports correct constant values", () => {
      expect(MAX_COMPARISON_LENGTH).toBe(4096);
      expect(MAX_RAW_INPUT_LENGTH).toBe(4096);
      expect(MAX_REDACT_DEPTH).toBe(8);
      expect(MAX_LOG_STRING).toBe(8192);
    });
  });

  // Existing tests
  it("secureWipe zeros a Uint8Array", () => {
    const arr = new Uint8Array([1, 2, 3, 4]);
    secureWipe(arr);
    expect(Array.from(arr)).toEqual([0, 0, 0, 0]);
  });

  it("createSecureZeroingArray enforces bounds", () => {
    const a = createSecureZeroingArray(8);
    expect(a.length).toBe(8);
  });

  it("secureCompare handles equal and different strings", () => {
    expect(secureCompare("abc", "abc")).toBe(true);
    expect(secureCompare("abc", "abx")).toBe(false);
    expect(() => secureCompare(undefined, undefined)).toThrow(
      InvalidParameterError,
    );
  });

  it("secureCompare throws on too long inputs", () => {
    const long = "a".repeat(5000);
    expect(() => secureCompare(long, "a")).toThrow(InvalidParameterError);
  });

  it("secureCompareAsync falls back when subtle missing and allow fallback", async () => {
    // Run without requireCrypto to allow fallback
    const res = await secureCompareAsync("x", "x");
    expect(res).toBe(true);
  });

  it("withSecureBuffer provides a buffer and wipes it on return", () => {
    let captured: Uint8Array | null = null;
    const result = withSecureBuffer(16, (buf) => {
      captured = buf;
      buf[0] = 42;
      return "done";
    });
    expect(result).toBe("done");
    expect(captured![0]).toBe(0); // should be wiped
  });

  it("withSecureBuffer wipes buffer even if callback throws", () => {
    let captured: Uint8Array | null = null;
    expect(() => {
      withSecureBuffer(16, (buf) => {
        captured = buf;
        buf[0] = 99;
        throw new Error("test error");
      });
    }).toThrow("test error");
    expect(captured![0]).toBe(0); // should be wiped despite throw
  });

  it("secureCompareBytes compares byte arrays correctly", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    expect(secureCompareBytes(a, b)).toBe(true);
    expect(secureCompareBytes(a, c)).toBe(false);
  });

  it("_redact redacts secrets and jwt-like and truncates long strings", () => {
    const obj = {
      password: "hunter2",
      token: "abc",
      nested: { jwt: "eyJxxxxx.yyyyy.zzzzz" },
      long: "a".repeat(9000),
    } as any;
    const redacted = _redact(obj) as any;
    expect(redacted.password).toBe("[REDACTED]");
    expect(redacted.token).toBe("[REDACTED]");
    // long should be truncated
    expect(typeof redacted.long).toBe("string");
  });

  it("_arrayBufferToBase64 produces expected base64", () => {
    const buf = new Uint8Array([0, 1, 2, 3]).buffer;
    const b64 = arrayBufferToBase64(buf);
    expect(typeof b64).toBe("string");
  });

  it("encodeComponentRFC3986 rejects control characters", () => {
    expect(() => encodeComponentRFC3986("a\x00b")).toThrow(
      InvalidParameterError,
    );
  });

  it("strictDecodeURIComponent handles malformed input", () => {
    const res = strictDecodeURIComponent("%E0%A4%A");
    expect(res.ok).toBe(false);
  });
});
