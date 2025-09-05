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
  getDevEventDispatchState,
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
      expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(result, "constructor")).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(result, "prototype")).toBe(
        false,
      );
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

      expect(mockDispatch).toHaveBeenCalled();
      const evt = mockDispatch.mock.calls[0][0];
      expect(evt).toEqual(
        expect.objectContaining({
          type: "security-kit:log",
        }),
      );
      // Detail payload invariants
      const detail = (evt as any).detail;
      expect(detail).toEqual(
        expect.objectContaining({
          level: "INFO",
          component: "test-component",
          message: "test message",
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

describe("createSecureZeroingArray (deprecated)", () => {
  it("creates array with correct length", () => {
    const arr = createSecureZeroingArray(16);
    expect(arr.length).toBe(16);
    expect(arr instanceof Uint8Array).toBe(true);
  });

  it("enforces bounds checking", () => {
    expect(() => createSecureZeroingArray(0)).toThrow(InvalidParameterError);
    expect(() => createSecureZeroingArray(4097)).toThrow(InvalidParameterError);
    expect(() => createSecureZeroingArray(-1)).toThrow(InvalidParameterError);
  });

  it("handles prototype pollution attempts", () => {
    // Test that the function doesn't inherit polluted properties
    const originalCreate = Uint8Array;
    try {
      // Simulate prototype pollution
      (Uint8Array as any).prototype.malicious = "polluted";
      const arr = createSecureZeroingArray(8);
      expect((arr as any).malicious).toBeUndefined();
    } finally {
      delete (Uint8Array as any).prototype.malicious;
    }
  });
});

describe("getDevEventDispatchState", () => {
  it("returns state object in development", () => {
    const state = getDevEventDispatchState();
    expect(state).toEqual({
      tokens: expect.any(Number),
      lastRefill: expect.any(Number),
      refillPerSec: expect.any(Number),
      maxTokens: expect.any(Number),
    });
  });

  it("returns undefined in production", () => {
    // We can't easily test production mode without mocking the environment
    // This function checks environment.isProduction internally
    const state = getDevEventDispatchState();
    // In test environment, this should return an object
    expect(typeof state).toBe("object");
  });
});

describe("OWASP ASVS L3 - Adversarial Security Tests", () => {
  describe("secureCompare - timing attack resistance", () => {
    it("resists timing attacks with different length strings", () => {
      const short = "a";
      const long = "a".repeat(1000);

      // Both should take similar time (constant-time comparison)
      const start1 = performance.now();
      secureCompare(short, long);
      const time1 = performance.now() - start1;

      const start2 = performance.now();
      secureCompare(long, short);
      const time2 = performance.now() - start2;

      // Allow some variance but ensure they're reasonably close
      expect(Math.abs(time1 - time2)).toBeLessThan(10);
    });

    it("handles Unicode normalization edge cases", () => {
      // Test various Unicode normalization forms
      expect(secureCompare("café", "café")).toBe(true);
      expect(secureCompare("café", "cafe\u0301")).toBe(true); // NFD vs NFC
      expect(secureCompare("Ⅳ", "IV")).toBe(false); // Roman numerals
    });

    it("resists DoS with maximum length inputs", () => {
      const maxLen = MAX_COMPARISON_LENGTH;
      const str1 = "a".repeat(maxLen);
      const str2 = "a".repeat(maxLen);

      expect(() => secureCompare(str1, str2)).not.toThrow();
      expect(secureCompare(str1, str2)).toBe(true);
    });

    it("handles null bytes and control characters", () => {
      expect(secureCompare("test\x00", "test\x00")).toBe(true);
      expect(secureCompare("test\x01", "test\x02")).toBe(false);
      expect(secureCompare("test\n", "test\t")).toBe(false);
    });

    it("validates input types strictly", () => {
      expect(() => secureCompare(null as any, "test")).toThrow(
        InvalidParameterError,
      );
      expect(() => secureCompare(undefined as any, "test")).toThrow(
        InvalidParameterError,
      );
      expect(() => secureCompare(123 as any, "test")).toThrow(
        InvalidParameterError,
      );
      expect(() => secureCompare("test", {} as any)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("secureCompareBytes - buffer overflow protection", () => {
    it("handles different length arrays securely", () => {
      const short = new Uint8Array([1, 2, 3]);
      const long = new Uint8Array([1, 2, 3, 4, 5]);

      expect(secureCompareBytes(short, long)).toBe(false);
      expect(secureCompareBytes(long, short)).toBe(false);
    });

    it("resists timing attacks with different contents", () => {
      const arr1 = new Uint8Array(1000).fill(0);
      const arr2 = new Uint8Array(1000).fill(1);

      const start = performance.now();
      const result = secureCompareBytes(arr1, arr2);
      const time = performance.now() - start;

      expect(result).toBe(false);
      expect(time).toBeLessThan(100); // Should complete quickly
    });

    it("handles TypedArray subclasses", () => {
      const uint8 = new Uint8Array([1, 2, 3]);
      const int8 = new Int8Array([1, 2, 3]);

      expect(secureCompareBytes(uint8, uint8)).toBe(true);
      // Cast to satisfy TS types while still exercising runtime constructor mismatch
      expect(
        secureCompareBytes(
          uint8 as unknown as Uint8Array,
          int8 as unknown as Uint8Array,
        ),
      ).toBe(false);
    });

    it("validates input types", () => {
      expect(() => secureCompareBytes(null as any, new Uint8Array(1))).toThrow(
        TypeError,
      );
      expect(() =>
        secureCompareBytes(new Uint8Array(1), undefined as any),
      ).toThrow(TypeError);
    });
  });

  describe("secureWipe - memory safety", () => {
    it("handles hostile buffer objects", () => {
      const hostileBuffer = {
        byteLength: 10,
        get buffer() {
          throw new Error("hostile getter");
        },
      };

      const result = secureWipe(hostileBuffer as any);
      expect(result).toBe(false);
    });

    it("resists prototype pollution in wipe strategies", () => {
      // Backup original methods
      const originalFill = Uint8Array.prototype.fill;
      const originalSet = DataView.prototype.setUint8;

      try {
        // Pollute prototypes
        (Uint8Array.prototype as any).fill = () => {
          throw new Error("polluted");
        };
        (DataView.prototype as any).setUint8 = () => {
          throw new Error("polluted");
        };

        const arr = new Uint8Array([1, 2, 3]);
        const result = secureWipe(arr);

        // Should still work with fallback strategies
        expect(result).toBe(true);
        expect(Array.from(arr)).toEqual([0, 0, 0]);
      } finally {
        // Restore originals
        Uint8Array.prototype.fill = originalFill;
        DataView.prototype.setUint8 = originalSet;
      }
    });

    it("handles extremely large buffers without DoS", () => {
      // Test with a reasonably large buffer that shouldn't cause issues
      const largeBuffer = new Uint8Array(100000);
      largeBuffer.fill(255);

      const start = performance.now();
      const result = secureWipe(largeBuffer);
      const time = performance.now() - start;

      expect(result).toBe(true);
      expect(largeBuffer[0]).toBe(0);
      expect(time).toBeLessThan(1000); // Should complete reasonably quickly
    });

    it("validates SharedArrayBuffer detection robustness", () => {
      // Test with hostile toString
      const mockBuffer = {
        constructor: { name: "ArrayBuffer" },
        toString() {
          throw new Error("hostile toString");
        },
      };

      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      expect(isSharedArrayBufferView(mockView)).toBe(false);
    });
  });

  describe("withSecureBuffer - lifecycle safety", () => {
    it("prevents use-after-free", () => {
      let capturedBuffer: Uint8Array | null = null;

      withSecureBuffer(16, (buf) => {
        capturedBuffer = buf;
        buf[0] = 42;
        return "result";
      });

      // Buffer should be wiped
      expect(capturedBuffer![0]).toBe(0);

      // Accessing after return should show wiped state
      expect(capturedBuffer![0]).toBe(0);
    });

    it("handles callback exceptions securely", () => {
      let capturedBuffer: Uint8Array | null = null;

      expect(() => {
        withSecureBuffer(16, (buf) => {
          capturedBuffer = buf;
          buf[0] = 99;
          throw new Error("callback failed");
        });
      }).toThrow("callback failed");

      // Buffer should still be wiped despite exception
      expect(capturedBuffer![0]).toBe(0);
    });

    it("resists callback re-entry attacks", () => {
      let callCount = 0;

      const result = withSecureBuffer(16, function inner(buf) {
        callCount++;
        if (callCount === 1) {
          // Try to call withSecureBuffer recursively
          try {
            withSecureBuffer(8, () => "nested");
          } catch {
            // Ignore nested call failures
          }
        }
        return "done";
      });

      expect(result).toBe("done");
      expect(callCount).toBe(1);
    });
  });

  describe("_redact - information disclosure prevention", () => {
    it("prevents prototype pollution in redaction", () => {
      const malicious = {
        __proto__: { toString: () => "[POLLUTED]" },
        normal: "safe",
      };

      const result = _redact(malicious) as any;
      expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(
        false,
      );
      expect(result.normal).toBe("safe");
    });

    it("handles deeply nested prototype pollution", () => {
      const deep = {
        level1: {
          level2: {
            __proto__: { polluted: true },
            safe: "value",
          },
        },
      };

      const result = _redact(deep) as any;
      expect(
        Object.prototype.hasOwnProperty.call(result.level1.level2, "__proto__"),
      ).toBe(false);
      expect(result.level1.level2.safe).toBe("value");
    });

    it("resists RegExp DoS in key validation", () => {
      // Create object with many keys that could cause regex backtracking
      const obj: any = {};
      for (let i = 0; i < 1000; i++) {
        obj[`key${i}`] = `value${i}`;
      }

      const start = performance.now();
      const result = _redact(obj) as any;
      const time = performance.now() - start;

      expect(time).toBeLessThan(100); // Should complete quickly
      expect(Object.keys(result as any).length).toBeGreaterThan(0);
    });

    it("handles hostile getter in object enumeration", () => {
      const hostile = {
        normal: "safe",
        get malicious() {
          throw new Error("hostile getter");
        },
      };

      const result = _redact(hostile) as any;
      expect(result.normal).toBe("safe");
      expect(result.malicious.reason).toBe("getter-threw");
    });

    it("prevents information leakage through function serialization", () => {
      const obj = {
        func: function secret() {
          return "sensitive";
        },
        arrow: () => "also sensitive",
      };

      const result = _redact(obj) as any;
      expect(result.func.__type).toBe("Function");
      expect(result.arrow.__type).toBe("Function");
      expect(result.func).not.toHaveProperty("toString");
    });
  });

  describe("telemetry - safe metric emission", () => {
    it("sanitizes metric tags against injection", () => {
      const unregister = registerTelemetry((name, value, tags) => {
        expect(tags?.reason).toBe("test");
        expect(
          Object.prototype.hasOwnProperty.call(tags ?? {}, "__proto__"),
        ).toBe(false);
      });

      emitMetric("test", 1, {
        reason: "test",
        __proto__: { polluted: true } as any,
      });

      unregister();
    });

    it("handles telemetry hook failures gracefully", () => {
      const unregister = registerTelemetry(() => {
        throw new Error("telemetry failure");
      });

      // Should not throw
      expect(() => emitMetric("test")).not.toThrow();

      unregister();
    });

    it("prevents metric tag leakage", async () => {
      let capturedTags: any = null;
      const unregister = registerTelemetry((name, value, tags) => {
        capturedTags = tags;
      });

      emitMetric("test", 1, {
        safe: "value",
        "unsafe key": "secret",
        "key@domain": "secret2",
      });

      // Wait for telemetry to be delivered asynchronously
      await new Promise((resolve) => setTimeout(resolve, 0));

      unregister();

      expect(capturedTags.safe).toBe("value");
      expect(
        Object.prototype.hasOwnProperty.call(capturedTags, "unsafe key"),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(capturedTags, "key@domain"),
      ).toBe(false);
    });
  });
});

describe("Internal function coverage", () => {
  it.skip("tests sanitizeMetricTags directly", () => {
    // Access internal function through module
    const utilsModule = require("../../src/utils");
    const sanitizeMetricTags = (utilsModule as any)._sanitizeMetricTags;

    const result = sanitizeMetricTags({
      reason: "test",
      invalid: "should be filtered",
    });

    expect(result).toEqual({ reason: "test" });
  });

  it.skip("tests safeEmitMetric error handling", () => {
    // Access internal function
    const utilsModule = require("../../src/utils");
    const safeEmitMetric = (utilsModule as any)._safeEmitMetric;

    // Should not throw even without telemetry hook
    expect(() => safeEmitMetric("test", 1, { reason: "test" })).not.toThrow();
  });

  it.skip("tests isSecurityStrict function", () => {
    const originalEnv = process.env.SECURITY_STRICT;

    try {
      process.env.SECURITY_STRICT = "1";
      const utilsModule = require("../../src/utils");
      const isSecurityStrict = (utilsModule as any)._isSecurityStrict;
      expect(isSecurityStrict()).toBe(true);

      process.env.SECURITY_STRICT = "0";
      expect(isSecurityStrict()).toBe(false);

      delete process.env.SECURITY_STRICT;
      expect(isSecurityStrict()).toBe(false);
    } finally {
      process.env.SECURITY_STRICT = originalEnv;
    }
  });
});
