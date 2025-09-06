import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  sanitizeLogMessage,
  sanitizeComponentName,
  isSharedArrayBufferView,
  secureDevLog,
  _devConsole,
  registerTelemetry,
  emitMetric,
  validateNumericParam,
  validateProbability,
  secureWipe,
  createSecureZeroingBuffer,
  withSecureBuffer,
  secureCompare,
  secureCompareAsync,
  secureCompareBytes,
  _redact,
  MAX_COMPARISON_LENGTH,
  MAX_RAW_INPUT_LENGTH,
  MAX_REDACT_DEPTH,
  MAX_LOG_STRING,
  MAX_ITEMS_PER_ARRAY,
  MAX_KEYS_PER_OBJECT,
  InvalidParameterError,
  IllegalStateError,
} from "../../src/utils";
import { CryptoUnavailableError } from "../../src/errors";
import { environment } from "../../src/environment";

describe("utils - uncovered branches", () => {
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
  });

  describe("sanitizeLogMessage edge cases", () => {
    it("handles empty strings", () => {
      expect(sanitizeLogMessage("")).toBe("");
    });

    it("handles strings with only whitespace", () => {
      expect(sanitizeLogMessage("   ")).toBe("   ");
    });

    it("handles strings with mixed case patterns", () => {
      const message = "PASSWORD=secret Token:abc SECRET=value";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("PASSWORD=[REDACTED]");
      expect(result).toContain("Token=[REDACTED]");
      expect(result).toContain("SECRET=[REDACTED]");
    });

    it("handles JWT-like tokens with different formats", () => {
      const messages = [
        "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.abc.def",
        "jwt: eyJhbGciOiJIUzI1NiJ9.xyz.abc",
        "bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.def.xyz",
      ];

      messages.forEach((msg) => {
        const result = sanitizeLogMessage(msg);
        expect(result).toContain("[REDACTED]");
        expect(result).not.toContain("eyJ");
      });
    });

    it("handles malformed JWT patterns (fail-closed)", () => {
      const malformed = [
        "token=eyJxxxxx", // incomplete
        "token=xxxxx.yyyyy.zzzzz", // not base64url
        "token=eyJxxxxx.yyyyy", // missing third part
        "token=xxxxx.yyyyy.zzzzz", // invalid base64url chars
      ];

      malformed.forEach((msg) => {
        const result = sanitizeLogMessage(msg);
        // Fail-closed: even malformed token-looking data should be redacted
        expect(result).toContain("[REDACTED]");
      });
    });

    it("handles authorization headers with various formats", () => {
      const messages = [
        "Authorization: Bearer token123",
        "authorization:bearer token123",
        "AUTHORIZATION = Bearer token123",
        "Authorization: Basic dXNlcjpwYXNz",
        "authorization: basic dXNlcjpwYXNz",
      ];

      messages.forEach((msg) => {
        const result = sanitizeLogMessage(msg);
        expect(result).toContain("Authorization=[REDACTED]");
      });
    });

    it("handles key=value patterns with special characters", () => {
      const message = "api_key=abc123 x-api-key:def456 secret_token=ghi789";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("api_key=[REDACTED]");
      expect(result).toContain("x-api-key=[REDACTED]");
      expect(result).toContain("secret_token=[REDACTED]");
    });

    it("handles overlapping patterns", () => {
      const message = "password=secret and authorization: Bearer token";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("password=[REDACTED]");
      // Canonical Authorization casing is used by sanitizer
      expect(result).toContain("Authorization=[REDACTED]");
    });

    it("handles very long tokens/values", () => {
      const longToken = "a".repeat(3000);
      const message = `token=${longToken}`;
      const result = sanitizeLogMessage(message);
      expect(result).toContain("token=[REDACTED]");
    });

    it("handles unicode characters in messages", () => {
      const message = "password=secret🔒 token=abc💡";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("password=[REDACTED]");
      expect(result).toContain("token=[REDACTED]");
    });

    it("handles messages with line breaks", () => {
      const message = "line1\npassword=secret\nline2\ntoken=abc";
      const result = sanitizeLogMessage(message);
      expect(result).toContain("password=[REDACTED]");
      expect(result).toContain("token=[REDACTED]");
    });

    it("handles sanitizer errors gracefully", () => {
      // Mock String.prototype.replace to throw
      const originalReplace = String.prototype.replace;
      String.prototype.replace = vi.fn().mockImplementation(() => {
        throw new Error("replace error");
      });

      try {
        const result = sanitizeLogMessage("password=secret");
        expect(result).toBe("[REDACTED]");
      } finally {
        String.prototype.replace = originalReplace;
      }
    });
  });

  describe("sanitizeComponentName edge cases", () => {
    it("handles null and undefined", () => {
      expect(sanitizeComponentName(null)).toBe("unsafe-component-name");
      expect(sanitizeComponentName(undefined)).toBe("unsafe-component-name");
    });

    it("handles objects and arrays", () => {
      expect(sanitizeComponentName({})).toBe("unsafe-component-name");
      expect(sanitizeComponentName([])).toBe("unsafe-component-name");
      expect(sanitizeComponentName({ toString: () => "safe" })).toBe(
        "unsafe-component-name",
      );
    });

    it("handles strings with special regex characters", () => {
      const unsafeNames = [
        "component[0]",
        "component{test}",
        "component(test)",
        "component+test",
        "component*test",
        "component?test",
        "component^test",
        "component$test",
        "component|test",
        "component.test", // dot is allowed
        "component-test", // dash is allowed
      ];

      unsafeNames.forEach((name) => {
        if (name.includes(".") || name.includes("-")) {
          expect(sanitizeComponentName(name)).toBe(name);
        } else {
          expect(sanitizeComponentName(name)).toBe("unsafe-component-name");
        }
      });
    });

    it("handles strings with unicode characters", () => {
      expect(sanitizeComponentName("component_测试")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("component-ñ")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("component_🚀")).toBe(
        "unsafe-component-name",
      );
    });

    it("handles strings at length boundaries", () => {
      const maxLengthName = "a".repeat(64);
      const tooLongName = "a".repeat(65);

      expect(sanitizeComponentName(maxLengthName)).toBe(maxLengthName);
      expect(sanitizeComponentName(tooLongName)).toBe("unsafe-component-name");
    });

    it("handles strings with control characters", () => {
      expect(sanitizeComponentName("component\x00name")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("component\nname")).toBe(
        "unsafe-component-name",
      );
      expect(sanitizeComponentName("component\tname")).toBe(
        "unsafe-component-name",
      );
    });

    it("handles strings starting or ending with special characters", () => {
      expect(sanitizeComponentName("_component")).toBe("_component");
      expect(sanitizeComponentName("component_")).toBe("component_");
      expect(sanitizeComponentName("-component")).toBe("-component");
      expect(sanitizeComponentName("component-")).toBe("component-");
      expect(sanitizeComponentName(".component")).toBe("unsafe-component-name");
      expect(sanitizeComponentName("component.")).toBe("unsafe-component-name");
    });
  });

  describe("isSharedArrayBufferView edge cases", () => {
    it("handles undefined and null inputs", () => {
      expect(isSharedArrayBufferView(undefined as any)).toBe(false);
      expect(isSharedArrayBufferView(null as any)).toBe(false);
    });

    it("handles non-object inputs", () => {
      expect(isSharedArrayBufferView(123 as any)).toBe(false);
      expect(isSharedArrayBufferView("string" as any)).toBe(false);
      expect(isSharedArrayBufferView(true as any)).toBe(false);
    });

    it("handles objects without buffer property", () => {
      expect(isSharedArrayBufferView({} as any)).toBe(false);
      expect(isSharedArrayBufferView({ byteLength: 10 } as any)).toBe(false);
    });

    it("handles buffer property that is not an object", () => {
      const view = { buffer: "not an object" } as any;
      expect(isSharedArrayBufferView(view)).toBe(false);
    });

    it("handles buffer.constructor.name manipulation", () => {
      const mockBuffer = { constructor: { name: "SharedArrayBuffer" } };
      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      // Mock toString to not return SharedArrayBuffer
      const originalToString = Object.prototype.toString;
      Object.prototype.toString = vi
        .fn()
        .mockReturnValue("[object ArrayBuffer]");

      expect(isSharedArrayBufferView(mockView)).toBe(false);

      Object.prototype.toString = originalToString;
    });

    it("handles instanceof check failures", () => {
      const mockBuffer = { constructor: { name: "SharedArrayBuffer" } };
      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      // Mock SharedArrayBuffer to throw on instanceof
      const originalSAB = globalThis.SharedArrayBuffer;
      Object.defineProperty(globalThis, "SharedArrayBuffer", {
        get: () => {
          throw new Error("instanceof error");
        },
        configurable: true,
      });

      try {
        expect(isSharedArrayBufferView(mockView)).toBe(false);
      } finally {
        Object.defineProperty(globalThis, "SharedArrayBuffer", {
          value: originalSAB,
          configurable: true,
        });
      }
    });

    it("handles missing SharedArrayBuffer constructor", () => {
      const originalSAB = globalThis.SharedArrayBuffer;
      delete (globalThis as any).SharedArrayBuffer;

      try {
        const view = new Uint8Array(10);
        expect(isSharedArrayBufferView(view)).toBe(false);
      } finally {
        (globalThis as any).SharedArrayBuffer = originalSAB;
      }
    });

    it("handles toStringTag manipulation", () => {
      const mockBuffer = {};
      Object.defineProperty(mockBuffer, Symbol.toStringTag, {
        value: "SharedArrayBuffer",
        enumerable: false,
      });

      const mockView = new Uint8Array(10);
      Object.defineProperty(mockView, "buffer", { value: mockBuffer });

      expect(isSharedArrayBufferView(mockView)).toBe(false); // Should use toString, not toStringTag
    });
  });

  describe("secureDevLog edge cases", () => {
    let mockDispatch: any;

    beforeEach(() => {
      mockDispatch = vi.fn();
      vi.spyOn(document, "dispatchEvent").mockImplementation(mockDispatch);
    });

    it("handles undefined context", () => {
      secureDevLog("info", "component", "message", undefined);
      expect(mockDispatch).toHaveBeenCalled();
    });

    it("handles null context", () => {
      secureDevLog("info", "component", "message", null);
      expect(mockDispatch).toHaveBeenCalled();
    });

    it("handles context with circular references", () => {
      const circular: any = { a: 1 };
      circular.self = circular;

      secureDevLog("info", "component", "message", circular);
      expect(mockDispatch).toHaveBeenCalled();
    });

    it("handles very long component names", () => {
      const longComponent = "a".repeat(1000);
      secureDevLog("info", longComponent, "message");
      expect(mockDispatch).toHaveBeenCalled();
      const call = mockDispatch.mock.calls[0][0];
      expect(call.detail.component).toBe("unsafe-component-name");
    });

    it("handles very long messages", () => {
      const longMessage = "a".repeat(10000);
      secureDevLog("info", "component", longMessage);
      expect(mockDispatch).toHaveBeenCalled();
      const call = mockDispatch.mock.calls[0][0];
      expect(call.detail.message.length).toBeLessThan(longMessage.length);
    });

    it("handles CustomEvent dispatch errors", () => {
      vi.spyOn(document, "dispatchEvent").mockImplementation(() => {
        throw new Error("dispatch error");
      });

      expect(() => {
        secureDevLog("info", "component", "message");
      }).not.toThrow();
    });

    it("handles missing document", () => {
      const originalDocument = globalThis.document;
      delete (globalThis as any).document;

      try {
        expect(() => {
          secureDevLog("info", "component", "message");
        }).not.toThrow();
      } finally {
        globalThis.document = originalDocument;
      }
    });

    it("handles missing CustomEvent", () => {
      const originalCustomEvent = globalThis.CustomEvent;
      delete (globalThis as any).CustomEvent;

      try {
        expect(() => {
          secureDevLog("info", "component", "message");
        }).not.toThrow();
      } finally {
        globalThis.CustomEvent = originalCustomEvent;
      }
    });
  });

  describe("_devConsole edge cases", () => {
    it("handles undefined context", () => {
      _devConsole("info", "message", undefined);
      expect(consoleInfoSpy).toHaveBeenCalled();
    });

    it("handles context serialization errors", () => {
      const badContext = {};
      Object.defineProperty(badContext, "badProp", {
        get: () => {
          throw new Error("getter error");
        },
      });

      _devConsole("info", "message", badContext);
      expect(consoleInfoSpy).toHaveBeenCalled();
    });

    it("handles very long context strings", () => {
      const longContext = { data: "a".repeat(2000) };
      _devConsole("info", "message", longContext);
      expect(consoleInfoSpy).toHaveBeenCalled();
      const call = consoleInfoSpy.mock.calls[0][0];
      expect(call.length).toBeLessThan(3000); // Should be truncated
    });

    it("handles context with sensitive data", () => {
      const context = { password: "secret", token: "abc123" };
      _devConsole("info", "message", context);
      expect(consoleInfoSpy).toHaveBeenCalled();
      const call = consoleInfoSpy.mock.calls[0][0];
      expect(call).toContain("[REDACTED]");
    });
  });

  describe("registerTelemetry edge cases", () => {
    it("handles non-function hooks", () => {
      expect(() => registerTelemetry("not a function" as any)).toThrow(
        InvalidParameterError,
      );
      expect(() => registerTelemetry(123 as any)).toThrow(
        InvalidParameterError,
      );
      expect(() => registerTelemetry(null as any)).toThrow(
        InvalidParameterError,
      );
      expect(() => registerTelemetry(undefined as any)).toThrow(
        InvalidParameterError,
      );
    });

    it("handles unregister callback being called multiple times", () => {
      const mockHook = vi.fn();
      const unregister = registerTelemetry(mockHook);

      unregister();
      unregister(); // Should be idempotent

      // Should be able to register again
      const unregister2 = registerTelemetry(mockHook);
      unregister2();
    });
  });

  describe("emitMetric edge cases", () => {
    it("handles telemetry hook errors", async () => {
      const mockHook = vi.fn().mockImplementation(() => {
        throw new Error("telemetry error");
      });
      const unregister = registerTelemetry(mockHook);

      expect(() => emitMetric("test")).not.toThrow();

      // Wait for microtask
      await new Promise((resolve) => setImmediate(resolve));

      unregister();
    });

    it("handles queueMicrotask unavailability", async () => {
      const originalQueueMicrotask = globalThis.queueMicrotask;
      delete (globalThis as any).queueMicrotask;

      const mockHook = vi.fn();
      const unregister = registerTelemetry(mockHook);

      emitMetric("test");

      // Should still work with Promise fallback
      await new Promise((resolve) => setImmediate(resolve));
      expect(mockHook).toHaveBeenCalled();

      unregister();
      globalThis.queueMicrotask = originalQueueMicrotask;
    });

    it("handles Promise unavailability", () => {
      const originalPromise = globalThis.Promise;
      const originalQueueMicrotask = globalThis.queueMicrotask;
      delete (globalThis as any).queueMicrotask;
      delete (globalThis as any).Promise;

      const mockHook = vi.fn();
      const unregister = registerTelemetry(mockHook);

      // Should not throw even without Promise
      expect(() => emitMetric("test")).not.toThrow();

      unregister();
      globalThis.Promise = originalPromise;
      globalThis.queueMicrotask = originalQueueMicrotask;
    });
  });

  describe("validateNumericParam edge cases", () => {
    it("handles NaN", () => {
      expect(() => validateNumericParam(NaN, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
    });

    it("handles Infinity", () => {
      expect(() => validateNumericParam(Infinity, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateNumericParam(-Infinity, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
    });

    it("handles floating point edge cases", () => {
      expect(() => validateNumericParam(5.0000000001, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateNumericParam(4.9999999999, "test", 0, 10)).toThrow(
        InvalidParameterError,
      );
    });

    it("handles very large numbers", () => {
      expect(() =>
        validateNumericParam(Number.MAX_SAFE_INTEGER + 1, "test", 0, 10),
      ).toThrow(InvalidParameterError);
    });

    it("handles negative zero", () => {
      validateNumericParam(-0, "test", -10, 10); // Should not throw
    });
  });

  describe("validateProbability edge cases", () => {
    it("handles NaN", () => {
      expect(() => validateProbability(NaN)).toThrow(InvalidParameterError);
    });

    it("handles Infinity", () => {
      expect(() => validateProbability(Infinity)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateProbability(-Infinity)).toThrow(
        InvalidParameterError,
      );
    });

    it("handles very small decimals", () => {
      validateProbability(Number.MIN_VALUE); // Should not throw
      validateProbability(Number.EPSILON); // Should not throw
    });

    it("handles boundary values", () => {
      validateProbability(0); // Should not throw
      validateProbability(1); // Should not throw
      expect(() => validateProbability(-Number.EPSILON)).toThrow(
        InvalidParameterError,
      );
      expect(() => validateProbability(1 + Number.EPSILON)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("secureWipe additional edge cases", () => {
    it("handles TypedArray subclasses", () => {
      class CustomUint8Array extends Uint8Array {}
      const arr = new CustomUint8Array([1, 2, 3]);
      const result = secureWipe(arr);
      expect(result).toBe(true);
      expect(Array.from(arr)).toEqual([0, 0, 0]);
    });

    it("handles DataView creation failures", () => {
      const arr = new Uint8Array([1, 2, 3]);
      // Mock DataView to throw
      const originalDataView = globalThis.DataView;
      globalThis.DataView = vi.fn().mockImplementation(() => {
        throw new Error("DataView error");
      });

      try {
        const result = secureWipe(arr);
        expect(result).toBe(true); // Should fall back to other strategies
      } finally {
        globalThis.DataView = originalDataView;
      }
    });

    it("handles BigInt array detection failures", () => {
      const arr = new BigUint64Array([1n, 2n, 3n]);
      // Mock BigUint64Array to throw on instanceof
      const originalBigUint64Array = globalThis.BigUint64Array;
      Object.defineProperty(globalThis, "BigUint64Array", {
        get: () => {
          throw new Error("BigInt error");
        },
        configurable: true,
      });

      try {
        const result = secureWipe(arr);
        expect(result).toBe(true); // Should fall back
      } finally {
        Object.defineProperty(globalThis, "BigUint64Array", {
          value: originalBigUint64Array,
          configurable: true,
        });
      }
    });

    it("handles fill method failures", () => {
      const arr = new Uint8Array([1, 2, 3]);
      // Mock fill to throw
      arr.fill = vi.fn().mockImplementation(() => {
        throw new Error("fill error");
      });

      const result = secureWipe(arr);
      expect(result).toBe(true); // Should fall back to byte-wise wipe
    });

    it("handles buffer property access failures", () => {
      const arr = new Uint8Array([1, 2, 3]);
      Object.defineProperty(arr, "buffer", {
        get: () => {
          throw new Error("buffer access error");
        },
      });

      const result = secureWipe(arr);
      expect(result).toBe(false); // Should fail gracefully
    });
  });

  describe("createSecureZeroingBuffer edge cases", () => {
    it("handles minimum and maximum sizes", () => {
      const minBuffer = createSecureZeroingBuffer(1);
      expect(minBuffer.get().length).toBe(1);

      const maxBuffer = createSecureZeroingBuffer(4096);
      expect(maxBuffer.get().length).toBe(4096);
    });

    it("handles buffer access after free", () => {
      const buffer = createSecureZeroingBuffer(16);
      buffer.free();

      expect(() => buffer.get()).toThrow(IllegalStateError);
    });

    it("handles multiple free calls", () => {
      const buffer = createSecureZeroingBuffer(16);
      expect(buffer.free()).toBe(true);
      expect(buffer.free()).toBe(true);
      expect(buffer.free()).toBe(true);
    });

    it("handles free after get", () => {
      const buffer = createSecureZeroingBuffer(16);
      const view = buffer.get();
      view[0] = 42;

      expect(buffer.free()).toBe(true);
      expect(view[0]).toBe(0); // Should be wiped
    });
  });

  describe("withSecureBuffer edge cases", () => {
    it("handles callback that modifies buffer", () => {
      const result = withSecureBuffer(16, (buf) => {
        buf.fill(42);
        return buf.length;
      });
      expect(result).toBe(16);
    });

    it("handles callback that returns complex objects", () => {
      const result = withSecureBuffer(16, (buf) => {
        return { buffer: buf, length: buf.length };
      });
      expect(result).toEqual({ buffer: expect.any(Uint8Array), length: 16 });
    });

    it("handles nested withSecureBuffer calls", () => {
      const result = withSecureBuffer(16, (outerBuf) => {
        return withSecureBuffer(8, (innerBuf) => {
          return outerBuf.length + innerBuf.length;
        });
      });
      expect(result).toBe(24);
    });
  });

  describe("secureCompare edge cases", () => {
    it("handles strings with unicode normalization differences", () => {
      // é can be represented as single codepoint or as e + combining acute
      const nfc = "café"; // NFC: single codepoint
      const nfd = "café"; // NFD: e + combining acute (but let's use a real difference)
      const angstrom1 = "Å"; // NFC
      const angstrom2 = "Å"; // NFD equivalent

      expect(secureCompare(angstrom1, angstrom2)).toBe(true);
    });

    it("handles strings at length boundaries", () => {
      const maxLength = MAX_COMPARISON_LENGTH;
      const atLimit = "a".repeat(maxLength);
      const overLimit = "a".repeat(maxLength + 1);

      expect(() => secureCompare(atLimit, atLimit)).not.toThrow();
      expect(() => secureCompare(overLimit, "a")).toThrow(
        InvalidParameterError,
      );
    });

    it("handles empty strings", () => {
      expect(secureCompare("", "")).toBe(true);
      expect(secureCompare("", "a")).toBe(false);
      expect(secureCompare("a", "")).toBe(false);
    });

    it("handles strings with null characters", () => {
      expect(secureCompare("a\x00b", "a\x00b")).toBe(true);
      expect(secureCompare("a\x00b", "a\x00c")).toBe(false);
    });

    it("handles strings with high unicode codepoints", () => {
      const emoji1 = "🚀";
      const emoji2 = "🚀";
      expect(secureCompare(emoji1, emoji2)).toBe(true);
    });
  });

  describe("secureCompareAsync additional edge cases", () => {
    it("handles crypto availability check failures", async () => {
      // Mock ensureCrypto to throw
      const stateModule = await import("../../src/state");
      const ensureCryptoSpy = vi.spyOn(stateModule, "ensureCrypto");
      ensureCryptoSpy.mockRejectedValue(new Error("crypto setup error"));

      try {
        await expect(
          secureCompareAsync("a", "b", { requireCrypto: true }),
        ).rejects.toThrow();
      } finally {
        ensureCryptoSpy.mockRestore();
      }
    });

    it("handles subtle.digest failures", async () => {
      const originalDigest = globalThis.crypto?.subtle?.digest;
      if (globalThis.crypto?.subtle) {
        // Tests should explicitly signal crypto unavailability by throwing
        // the library's CryptoUnavailableError so intent is unambiguous.
        globalThis.crypto.subtle.digest = vi
          .fn()
          .mockRejectedValue(new CryptoUnavailableError());
      }

      try {
        const result = await secureCompareAsync("a", "b");
        expect(result).toBe(false); // Should fall back to sync when crypto unavailable
      } finally {
        if (globalThis.crypto?.subtle && originalDigest) {
          globalThis.crypto.subtle.digest = originalDigest;
        }
      }
    });

    it("handles Promise.all failures", async () => {
      const originalAll = Promise.all;
      Promise.all = vi.fn().mockRejectedValue(new Error("Promise.all error"));

      try {
        const result = await secureCompareAsync("a", "b");
        expect(result).toBe(false); // Should fall back
      } finally {
        Promise.all = originalAll;
      }
    });
  });

  describe("secureCompareBytes edge cases", () => {
    it("handles empty arrays", () => {
      const empty1 = new Uint8Array(0);
      const empty2 = new Uint8Array(0);
      expect(secureCompareBytes(empty1, empty2)).toBe(true);
    });

    it("handles arrays of different lengths", () => {
      const short = new Uint8Array([1, 2]);
      const long = new Uint8Array([1, 2, 3]);
      expect(secureCompareBytes(short, long)).toBe(false);
    });

    it("handles arrays with zeros", () => {
      const zeros1 = new Uint8Array([0, 0, 0]);
      const zeros2 = new Uint8Array([0, 0, 0]);
      expect(secureCompareBytes(zeros1, zeros2)).toBe(true);
    });

    it("handles large arrays", () => {
      const large1 = new Uint8Array(10000).fill(42);
      const large2 = new Uint8Array(10000).fill(42);
      const large3 = new Uint8Array(10000).fill(43);

      expect(secureCompareBytes(large1, large2)).toBe(true);
      expect(secureCompareBytes(large1, large3)).toBe(false);
    });
  });

  describe("_redact additional edge cases", () => {
    it("handles objects with symbol properties", () => {
      const sym = Symbol("test");
      const obj = { [sym]: "value", normal: "prop" };
      const result = _redact(obj) as any;

      expect(result.__symbol_key_count__).toBe(1);
      expect(result.normal).toBe("prop");
    });

    it("handles symbol property enumeration failures", () => {
      const obj = {};
      Object.defineProperty(obj, "nonEnum", {
        value: "test",
        enumerable: false,
      });

      const result = _redact(obj);
      expect(result).toBeDefined();
    });

    it("handles RegExp objects", () => {
      const regex = /test/gi;
      const result = _redact(regex);
      expect(typeof result).toBe("object");
    });

    it("handles function objects", () => {
      const func = () => {};
      const result = _redact(func);
      expect(typeof result).toBe("object");
    });

    it("handles depth limit exceeded", () => {
      const deep = { level: 0 };
      let current = deep;
      for (let i = 1; i <= MAX_REDACT_DEPTH + 1; i++) {
        current.nested = { level: i };
        current = current.nested as any;
      }

      const result = _redact(deep) as any;
      expect(result.nested.__redacted).toBe(true);
      expect(result.nested.reason).toBe("max-depth");
    });

    it("handles breadth limits for arrays", () => {
      const largeArray = Array.from(
        { length: MAX_ITEMS_PER_ARRAY + 10 },
        (_, i) => i,
      );
      const result = _redact(largeArray) as any[];

      expect(result.length).toBeGreaterThan(MAX_ITEMS_PER_ARRAY);
      expect(result[result.length - 1].__truncated).toBe(true);
    });

    it("handles breadth limits for objects", () => {
      const largeObj: any = {};
      for (let i = 0; i < MAX_KEYS_PER_OBJECT + 10; i++) {
        largeObj[`key${i}`] = `value${i}`;
      }

      const result = _redact(largeObj) as any;
      expect(result.__additional_keys__).toBeDefined();
      expect(result.__additional_keys__.__truncated).toBe(true);
    });
  });
});
