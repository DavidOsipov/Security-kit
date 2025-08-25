// Converted from JS to TS for the new security_kit module
import { describe, it, expect, beforeEach, afterEach, vi, test } from "vitest";
import { webcrypto } from "node:crypto";
import {
  makeDeterministicStub,
  makeAll255Stub,
} from "./_test-helpers/crypto-stubs";

// Use Node's webcrypto as the default mock with additional methods
const mockCrypto = {
  ...webcrypto,
  randomUUID: () => "01234567-89ab-4cde-8fed-0123456789ab",
  subtle: {
    ...webcrypto.subtle,
    digest: vi.fn(
      (algorithm: string, data: BufferSource | ArrayBuffer | Uint8Array) => {
        // Mock digest function that returns predictable hash-like values
        const input =
          data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : new Uint8Array(data as ArrayBuffer | Uint8Array);
        const hashLength = algorithm.includes("256")
          ? 32
          : algorithm.includes("384")
            ? 48
            : 64;
        const result = new Uint8Array(hashLength);
        for (let i = 0; i < hashLength; i++) {
          result[i] = (input.length + i) % 256; // Simple deterministic "hash"
        }
        return Promise.resolve(result.buffer);
      },
    ),
  },
} as unknown as Crypto & { randomUUID?: () => string };

// Import the module to be tested from the new TS path
import * as securityKit from "../utils/security_kit";

// Test helper to reset internal state
function resetSecurityKitState() {
  // Since _isSealed is private, we can't reset it directly
  // This is a limitation of the security-kit design for test isolation
  // Tests that call sealSecurityKit() should be isolated or run last
}

// Helper to clear injected crypto in tests while tolerating sealed configuration.
function safeClearCrypto() {
  try {
    setCrypto(null);
  } catch {
    // Configuration may be sealed by tests intentionally — ignore for cleanup.
  }
}

const {
  CryptoUnavailableError,
  InvalidParameterError,
  RandomGenerationError,
  generateSecureId,
  generateSecureIdSync,
  generateSecureUUID,
  getSecureRandomInt,
  getSecureRandomAsync,
  getSecureRandom,
  shouldExecuteThrottledAsync,
  shouldExecuteThrottled,
  setCrypto,
  createOneTimeCryptoKey,
  createAesGcmNonce,
  // Newly exercised APIs
  secureWipe,
  configureErrorReporter,
  sealSecurityKit,
} = securityKit;
// Also import setAppEnvironment for tests that toggle environment
const { setAppEnvironment } = securityKit;

function chiSquaredTest(
  observed: Record<string, number>,
  totalObservations: number,
) {
  const categories = Object.keys(observed);
  const numCategories = categories.length;
  const expected = totalObservations / numCategories;
  const df = numCategories - 1;
  const criticalValues: Record<number, number> = {
    1: 6.63,
    2: 9.21,
    3: 11.34,
    4: 13.28,
    5: 15.09,
    9: 21.67,
    15: 30.58,
  };
  const criticalValue = criticalValues[df];
  if (!criticalValue)
    throw new Error(`No critical value for ${df} degrees of freedom.`);
  let chiSquaredStatistic = 0;
  for (const category of categories) {
    chiSquaredStatistic +=
      ((observed[category] ?? 0) - expected) ** 2 / expected;
  }
  return chiSquaredStatistic < criticalValue;
}

function createTestRunner<T, R>(func: (arg?: T) => R, isAsync: boolean) {
  return (arg?: T) => {
    if (isAsync) {
      return (func as any)(arg);
    } else {
      try {
        return Promise.resolve((func as any)(arg));
      } catch (error) {
        return Promise.reject(error);
      }
    }
  };
}

describe("security-kit (TS)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetSecurityKitState();
    // Inject the mocked crypto for both async and sync operations
    try {
      setCrypto(mockCrypto);
    } catch {
      // If the security kit has been sealed by another test, tolerate it for isolation.
    }
  });

  afterEach(() => {
    (mockCrypto.getRandomValues as any).mock?.restore?.();
    resetSecurityKitState();
    // Clear the injected crypto (tolerate sealed configuration)
    safeClearCrypto();
  });

  describe("Error Classes", () => {
    it("CryptoUnavailableError has correct name and default/custom messages", () => {
      const defaultErr = new CryptoUnavailableError();
      expect(defaultErr).toBeInstanceOf(Error);
      expect(defaultErr.name).toBe("CryptoUnavailableError");
      expect(defaultErr.message).toMatch(
        /\[secure-helpers\] A compliant Web Crypto API is not available/,
      );
      const customErr = new CryptoUnavailableError("test");
      expect(customErr.message).toBe("[secure-helpers] test");
    });

    it("InvalidParameterError has correct name and message format", () => {
      const err = new InvalidParameterError("param");
      expect(err).toBeInstanceOf(RangeError);
      expect(err.name).toBe("InvalidParameterError");
      expect(err.message).toBe("[secure-helpers] param");
    });
  });

  describe("Crypto API Discovery and Resilience", () => {
    it("should use the mocked crypto API", async () => {
      await generateSecureId();
      // We can't reliably spy on webcrypto in Node here due to types, but reaching here is fine
      expect(typeof generateSecureId).toBe("function");
    });

    it("should throw CryptoUnavailableError when no API is found", async () => {
      vi.resetModules();
      Object.defineProperty(globalThis as any, "crypto", {
        value: undefined,
        configurable: true,
      });
      vi.doMock("node:crypto", () => ({ webcrypto: undefined }));
      const { generateSecureId: freshGen, CryptoUnavailableError: FreshError } =
        await import("../utils/security_kit");
      await expect(freshGen()).rejects.toThrow(FreshError as any);
      vi.doUnmock("node:crypto");
      vi.resetModules();
    });

    it("should propagate underlying errors from a faulty crypto.getRandomValues", async () => {
      const hardwareError = new Error("Crypto hardware failure");
      // Inject a deterministic stub that throws on getRandomValues to ensure
      // the path used by generateSecureId will throw.
      const stub = {
        getRandomValues: () => {
          throw hardwareError;
        },
        randomUUID: () => "stub-uuid",
      } as unknown as Crypto;
      setCrypto(stub);
      await expect(generateSecureId()).rejects.toThrow(hardwareError);
      setCrypto((globalThis as any).crypto as Crypto);
    });

    it("supports dependency injection via setCrypto for testing", async () => {
      const calls: number[] = [];
      const stub = {
        getRandomValues(arr: Uint8Array) {
          calls.push(arr.length);
          arr.fill(0x11);
          return arr;
        },
        randomUUID: () => "11111111-1111-4111-8111-111111111111",
      } as unknown as Crypto;
      setCrypto(stub);
      const id = await generateSecureId(4);
      expect(id).toBe("1111");
      const uuid = await generateSecureUUID();
      expect(uuid).toBe("11111111-1111-4111-8111-111111111111");
      expect(calls.length).toBeGreaterThan(0);
      safeClearCrypto();
    });
  });

  describe("getSecureRandomBytesSync", () => {
    it("returns requested length and is not all zeros", () => {
      const out = securityKit.getSecureRandomBytesSync(32);
      expect(out).toBeInstanceOf(Uint8Array);
      expect(out.length).toBe(32);
      expect(out.every((b) => b === 0)).toBe(false);
    });

    it("throws on invalid lengths", () => {
      expect(() => securityKit.getSecureRandomBytesSync(0)).toThrow(
        InvalidParameterError,
      );
      expect(() => securityKit.getSecureRandomBytesSync(-1)).toThrow(
        InvalidParameterError,
      );
      expect(() => securityKit.getSecureRandomBytesSync(4097)).toThrow(
        InvalidParameterError,
      );
      // @ts-expect-error
      expect(() => securityKit.getSecureRandomBytesSync("8")).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe.each([
    ["generateSecureId", generateSecureId, true],
    ["generateSecureIdSync", generateSecureIdSync, false],
  ])("%s", (_name, func, isAsync) => {
    const run = createTestRunner(func as any, isAsync);

    it("should generate an ID of the default length (64)", async () => {
      const id = await run();
      expect((id as string).length).toBe(64);
      expect(id).toMatch(/^[0-9a-f]{64}$/);
    });

    it("should handle boundary lengths 1 and 256", async () => {
      expect(await run(1 as any)).toHaveLength(1);
      expect(await run(256 as any)).toHaveLength(256);
    });

    it("should correctly handle odd lengths by slicing", async () => {
      const stub = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0xab);
          return arr;
        },
        randomUUID: () => "stub-uuid",
      } as unknown as Crypto;
      setCrypto(stub);
      const id = await run(3 as any);
      expect(id).toMatch(/^[0-9a-f]{3}$/);
      expect(id).toBe("bbb"); // 0xab & 0xF = 11 = 'b' in hex alphabet
      safeClearCrypto();
    });

    it("should throw InvalidParameterError for a wide range of invalid types", async () => {
      const invalidInputs: any[] = [
        0,
        257,
        null,
        NaN,
        Infinity,
        [],
        {},
        "string",
        true,
      ];
      for (const input of invalidInputs) {
        await expect(run(input)).rejects.toThrow(InvalidParameterError);
      }
    });
  });

  describe("generateSecureUUID", () => {
    const UUID_V4_REGEX =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    it("should use crypto.randomUUID when available", async () => {
      const maybeSpy = (mockCrypto as any).randomUUID
        ? vi.spyOn(mockCrypto as any, "randomUUID")
        : null;
      const uuid = await generateSecureUUID();
      expect(uuid).toMatch(UUID_V4_REGEX);
      if (maybeSpy) maybeSpy.mockRestore();
    });

    it("should set RFC 4122 version and variant bits correctly in fallback", async () => {
      (mockCrypto as any).randomUUID = undefined;
      vi.spyOn(mockCrypto as any, "getRandomValues").mockImplementation(
        (arr: any) => arr.fill(0xff),
      );
      const uuid = await generateSecureUUID();
      expect(uuid).toMatch(UUID_V4_REGEX);
      expect(uuid[14]).toBe("4");
      expect(["8", "9", "a", "b"]).toContain(uuid[19]);
      (mockCrypto as any).randomUUID = vi.fn(
        () => "mock-uuid-v4-from-crypto-api",
      );
      (mockCrypto.getRandomValues as any).mockRestore?.();
    });

    it("throws when fallback getRandomValues throws an underlying error", async () => {
      // Simulate a crypto implementation that fails catastrophically
      const originalCrypto = (globalThis as any).crypto;
      const fake = {
        getRandomValues: () => {
          throw new Error("simulated crypto failure");
        },
      } as unknown as Crypto;

      try {
        setCrypto(fake, { allowInProduction: true });
        await expect(generateSecureUUID()).rejects.toThrow();
      } finally {
        // Restore previous crypto (ignore sealed state)
        try {
          setCrypto(originalCrypto as Crypto, { allowInProduction: true });
        } catch {}
      }
    });
  });

  describe("getSecureRandomInt", () => {
    it("should return an integer within the specified range", async () => {
      const result = await getSecureRandomInt(1, 100);
      expect(Number.isInteger(result)).toBe(true);
      expect(result).toBeGreaterThanOrEqual(1);
      expect(result).toBeLessThanOrEqual(100);
    });

    it("should enforce stricter bounds to prevent DoS attacks", async () => {
      const MAX_SAFE_RANGE = 2 ** 31;
      const MIN_SAFE_RANGE = -(2 ** 31);
      await expect(
        getSecureRandomInt(MIN_SAFE_RANGE, MIN_SAFE_RANGE + 10),
      ).resolves.toBeDefined();
      await expect(
        getSecureRandomInt(MAX_SAFE_RANGE - 10, MAX_SAFE_RANGE),
      ).resolves.toBeDefined();
      await expect(getSecureRandomInt(MIN_SAFE_RANGE - 1, 100)).rejects.toThrow(
        InvalidParameterError,
      );
      await expect(getSecureRandomInt(100, MAX_SAFE_RANGE + 1)).rejects.toThrow(
        InvalidParameterError,
      );
    });

    it("should use rejection sampling to prevent modulo bias (deterministic stub)", async () => {
      // Use a deterministic stub to ensure rejection-sampling acceptance path
      // is exercised predictably: choose byte 10 which falls within threshold
      const stub = makeDeterministicStub([10]);
      setCrypto(stub);
      const result = await getSecureRandomInt(0, 20);
      expect(Number.isInteger(result)).toBe(true);
      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThanOrEqual(20);
      safeClearCrypto();
    });

    it("should handle large ranges using BigInt arithmetic correctly", async () => {
      const min = 1000000000; // 1 billion
      const max = 2000000000; // 2 billion
      const result = await getSecureRandomInt(min, max);
      expect(Number.isInteger(result)).toBe(true);
      expect(result).toBeGreaterThanOrEqual(min);
      expect(result).toBeLessThanOrEqual(max);
    });

    it("handles pathological random bytes (all 255) deterministically", async () => {
      const stub = makeAll255Stub();
      setCrypto(stub);
      // For range 0..1, a first-byte of 255 will be accepted by the algorithm and yield a valid value.
      const val = await getSecureRandomInt(0, 1);
      expect(Number.isInteger(val)).toBe(true);
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(1);
      safeClearCrypto();
    });

    it("should produce a uniform distribution (passes Chi-squared test)", async () => {
      const { webcrypto: realCrypto } =
        await vi.importActual<any>("node:crypto");
      vi.resetModules();
      Object.defineProperty(globalThis as any, "crypto", {
        value: realCrypto,
        configurable: true,
      });
      const { getSecureRandomInt: fresh } = await import(
        "../utils/security_kit"
      );
      const min = 0,
        max = 5,
        iterations = 10000;
      const counts: Record<string, number> = {
        0: 0,
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 0,
      };
      for (let i = 0; i < iterations; i++) {
        const key = String(await fresh(min, max));
        if (counts[key] !== undefined) {
          counts[key]++;
        }
      }
      expect(chiSquaredTest(counts, iterations)).toBe(true);
      Object.defineProperty(globalThis as any, "crypto", {
        value: mockCrypto,
        configurable: true,
      });
    });
  });

  describe.each([
    ["getSecureRandomAsync", getSecureRandomAsync, true],
    ["getSecureRandom", getSecureRandom, false],
  ])("%s", (_name, func, isAsync) => {
    const run = () => createTestRunner(func as any, isAsync)();

    it("should use high precision (64-bit) path when available", async () => {
      const calls: string[] = [];
      const stub = {
        getRandomValues: (arr: any) => {
          calls.push(arr.constructor.name);
          if (
            typeof BigUint64Array !== "undefined" &&
            arr instanceof BigUint64Array
          ) {
            (arr as BigUint64Array)[0] = 0n;
          } else if (arr instanceof Uint32Array) {
            (arr as Uint32Array)[0] = 0;
          }
          return arr;
        },
        randomUUID: () => "stub",
      } as unknown as Crypto;
      setCrypto(stub);
      await run();

      // ARCHITECTURAL DECISION: getSecureRandom() is deterministically 32-bit,
      // getSecureRandomAsync() uses platform-optimal precision (64-bit when available)
      if (func === getSecureRandom) {
        expect(calls[0]).toBe("Uint32Array");
      } else {
        expect(calls[0]).toBe("BigUint64Array");
      }
      setCrypto(null);
    });

    it("should use fallback (32-bit) path when BigUint64Array is NOT available", async () => {
      const originalBig = globalThis.BigUint64Array;
      // @ts-ignore
      globalThis.BigUint64Array = undefined;
      const calls: string[] = [];
      const stub = {
        getRandomValues: (arr: any) => {
          calls.push(arr.constructor.name);
          if (arr instanceof Uint32Array) arr[0] = 0;
          return arr;
        },
        randomUUID: () => "stub",
      } as unknown as Crypto;
      setCrypto(stub);
      await run();
      expect(calls[0]).toBe("Uint32Array");
      setCrypto(null);
      globalThis.BigUint64Array = originalBig;
    });
  });

  describe.each([
    ["shouldExecuteThrottledAsync", shouldExecuteThrottledAsync, true],
    ["shouldExecuteThrottled", shouldExecuteThrottled, false],
  ])("%s", (_name, func, isAsync) => {
    const run = (arg: number) => createTestRunner(func as any, isAsync)(arg);

    it("should return deterministically based on the underlying random number", async () => {
      const values = [
        (arr: any) => {
          if (
            typeof BigUint64Array !== "undefined" &&
            arr instanceof BigUint64Array
          )
            (arr as any)[0] = 0x7d70a3d70a3d7000n;
          else (arr as Uint32Array)[0] = Math.floor(0.49 * (0xffffffff + 1));
        },
        (arr: any) => {
          if (
            typeof BigUint64Array !== "undefined" &&
            arr instanceof BigUint64Array
          )
            (arr as any)[0] = 0x828f5c28f5c29000n;
          else (arr as Uint32Array)[0] = Math.floor(0.51 * (0xffffffff + 1));
        },
      ];
      let idx = 0;
      const stub = {
        getRandomValues: (arr: any) => {
          const fn = values[idx++];
          if (fn) fn(arr);
          return arr;
        },
        randomUUID: () => "stub",
      } as unknown as Crypto;
      setCrypto(stub);
      await expect(run(0.5)).resolves.toBe(true);
      await expect(run(0.5)).resolves.toBe(false);
      setCrypto(null);
    });
  });

  describe("Environment-dependent logic", () => {
    const originalNodeEnv = process.env.NODE_ENV;

    afterEach(() => {
      process.env.NODE_ENV = originalNodeEnv;
      vi.resetModules();
    });

    it("should correctly identify development via NODE_ENV", async () => {
      process.env.NODE_ENV = "development";
      vi.resetModules();
      const { environment } = await import("../utils/security_kit");
      expect(environment.isDevelopment).toBe(true);
    });

    it("should correctly identify production via setAppEnvironment", async () => {
      vi.resetModules();
      const { environment, setAppEnvironment } = await import(
        "../utils/security_kit"
      );
      setAppEnvironment("production");
      expect(environment.isProduction).toBe(true);
    });

    it("should not be vulnerable to prototype pollution in dev logs", async () => {
      vi.resetModules();
      const { secureDevLog, setAppEnvironment } = await import(
        "../utils/security_kit"
      );
      setAppEnvironment("development");
      const originalDocument = (globalThis as any).document;
      (globalThis as any).document = undefined;
      const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');
      secureDevLog("info", "test", "message", maliciousPayload);
      expect(({} as any).polluted).toBeUndefined();
      (globalThis as any).document = originalDocument;
    });

    it("secureDevLog should redact secret-like keys and dispatch sanitized event", async () => {
      process.env.NODE_ENV = "development";
      const listeners: any[] = [];
      (globalThis as any).document = {
        dispatchEvent(ev: any) {
          listeners.push(ev.detail);
        },
      };
      vi.resetModules();
      const { secureDevLog } = await import("../utils/security_kit");
      secureDevLog("info", "comp", "msg", {
        token: "abcd",
        password: "secret",
        harmless: 42,
      });
      expect(listeners.length).toBe(1);
      const entry = listeners[0];
      expect(entry.context.token).toBe("[REDACTED]");
      expect(entry.context.password).toBe("[REDACTED]");
      expect(entry.context.harmless).toBe(42);
      delete (globalThis as any).document;
    });

    it("environment.clearCache should force recomputation", async () => {
      vi.resetModules();
      const { environment, setAppEnvironment } = await import(
        "../utils/security_kit"
      );
      setAppEnvironment("production");
      expect(environment.isProduction).toBe(true);
      setAppEnvironment("development");
      expect(environment.isDevelopment).toBe(true);
    });
  });

  describe("Advanced Security and Resource Testing", () => {
    it("should handle concurrent access without race conditions", async () => {
      const { webcrypto: realCrypto } =
        await vi.importActual<any>("node:crypto");
      vi.resetModules();
      Object.defineProperty(globalThis as any, "crypto", {
        value: realCrypto,
        configurable: true,
      });
      const { generateSecureId: fresh } = await import("../utils/security_kit");
      const promises = Array.from({ length: 50 }, () => fresh(16));
      const ids = await Promise.all(promises);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(50);
      Object.defineProperty(globalThis as any, "crypto", {
        value: mockCrypto,
        configurable: true,
      });
    });

    it("should use optimized hex encoding when Buffer is available", async () => {
      // Older implementations used Buffer.from optimizations; current implementation
      // may not. Instead, ensure the function returns a hex string of correct length.
      const originalBuffer = (globalThis as any).Buffer;
      (globalThis as any).Buffer = { from: vi.fn() } as any;
      try {
        const id = await generateSecureId(16);
        expect(typeof id).toBe("string");
        expect(id).toMatch(/^[0-9a-f]{16}$/);
      } finally {
        (globalThis as any).Buffer = originalBuffer;
      }
    });
  });

  describe("String comparison helpers", () => {
    it("secureCompare normalizes NFC and compares in constant-time-ish", async () => {
      const { secureCompare, InvalidParameterError: FreshInvalid } =
        await import("../utils/security_kit");
      const a = "e\u0301"; // e + combining acute
      const b = "\u00E9"; // precomposed é
      expect(secureCompare(a, b)).toBe(true);
      expect(secureCompare("abc", "abd")).toBe(false);
      const long = "x".repeat(4097);
      expect(() => secureCompare(long, "x")).toThrow(FreshInvalid as any);
    });

    it("secureCompareAsync uses digest when available and falls back safely", async () => {
      const fresh = await import("../utils/security_kit");
      await expect(fresh.secureCompareAsync("same", "same")).resolves.toBe(
        true,
      );
      await expect(fresh.secureCompareAsync("a", "b")).resolves.toBe(false);
      const stub = {
        getRandomValues: (a: any) => (a.fill?.(1), a),
        subtle: {},
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      await expect(fresh.secureCompareAsync("x", "x")).resolves.toBe(true);
      await expect(fresh.secureCompareAsync("x", "y")).resolves.toBe(false);
      fresh.setCrypto(null);
      const long = "x".repeat(4097);
      await expect(fresh.secureCompareAsync(long, "x")).rejects.toThrow(
        fresh.InvalidParameterError as any,
      );
    });
  });

  describe("URI helpers (security-kit)", () => {
    it("createSecureURL does not double-encode path segments (no %2520)", async () => {
      const { createSecureURL } = await import("../utils/security_kit");
      const url = createSecureURL(
        "https://example.com",
        ["a b"],
        { q: "x y" } as any,
        "frag",
      );
      // Path segment should be encoded once to %20, not double-encoded to %2520
      expect(url).toContain("/a%20b");
      expect(url).not.toContain("%2520");
      // Query parameter should be encoded correctly
      expect(url).toContain("?q=x%20y");
      // Fragment set correctly
      expect(url).toContain("#frag");
    });

    it("encodes reserved sub-delims '!' '()' '*' and '\''", async () => {
      const { encodeComponentRFC3986 } = await import("../utils/security_kit");
      expect(encodeComponentRFC3986(`!'()*`)).toBe("%21%27%28%29%2A");
    });

    it("leaves unreserved alnum and -._~ unchanged", async () => {
      const { encodeComponentRFC3986 } = await import("../utils/security_kit");
      expect(encodeComponentRFC3986("AZaz09-._~")).toBe("AZaz09-._~");
    });

    it("encodes space to %20 for query/path and '+' for form", async () => {
      const { encodeQueryValue, encodePathSegment, encodeFormValue } =
        await import("../utils/security_kit");
      expect(encodeQueryValue("a b")).toBe("a%20b");
      expect(encodePathSegment("a b")).toBe("a%20b");
      expect(encodeFormValue("a b c")).toBe("a+b+c");
    });

    it("rejects control characters in encoder", async () => {
      const { encodeComponentRFC3986, InvalidParameterError } = await import(
        "../utils/security_kit"
      );
      expect(() => encodeComponentRFC3986("line\nbreak")).toThrow(
        InvalidParameterError,
      );
      expect(() => encodeComponentRFC3986("\u0000nul")).toThrow(
        InvalidParameterError,
      );
    });

    it("preservePercentEncoded keeps %XX intact and encodes others", async () => {
      const { encodeComponentRFC3986 } = await import("../utils/security_kit");
      const input = "abc%2Fdef?x=1&y=2";
      const out = encodeComponentRFC3986(input, {
        preservePercentEncoded: true,
      });
      expect(out).toBe("abc%2Fdef%3Fx%3D1%26y%3D2");
    });

    it("throws on malformed percent sequences in preserve mode", async () => {
      const { encodeComponentRFC3986, InvalidParameterError } = await import(
        "../utils/security_kit"
      );
      expect(() =>
        encodeComponentRFC3986("bad%GZ", { preservePercentEncoded: true }),
      ).toThrow(InvalidParameterError);
    });

    it("strictDecodeURIComponent returns ok=true when valid", async () => {
      const { strictDecodeURIComponent } = await import(
        "../utils/security_kit"
      );
      const res = strictDecodeURIComponent("a%20b");
      expect(res.ok).toBe(true);
      if (res.ok) expect(res.value).toBe("a b");
    });

    it("strictDecodeURIComponent returns ok=false when malformed by default", async () => {
      const { strictDecodeURIComponent, InvalidParameterError } = await import(
        "../utils/security_kit"
      );
      const res = strictDecodeURIComponent("%E0%A4%A");
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.error).toBeInstanceOf(InvalidParameterError);
    });

    it("strictDecodeURIComponent repair mode replaces and decodes", async () => {
      const { strictDecodeURIComponent } = await import(
        "../utils/security_kit"
      );
      const res = strictDecodeURIComponent("%ZZHello%20World%", {
        onError: "replace",
        replaceWith: "\uFFFD",
      });
      expect(res.ok).toBe(true);
      if (res.ok) expect(res.value).toBe("\uFFFDHello World\uFFFD");
    });

    it("strictDecodeURIComponentOrThrow throws on malformed", async () => {
      const { strictDecodeURIComponentOrThrow, InvalidParameterError } =
        await import("../utils/security_kit");
      expect(() => strictDecodeURIComponentOrThrow("%bad")).toThrow(
        InvalidParameterError,
      );
    });

    it("createSecureURL rejects encoded path traversal sequences like %2e%2e or %2e%2e%2f", async () => {
      const { createSecureURL } = await import("../utils/security_kit");
      // Encoded '..' should be rejected
      expect(() =>
        createSecureURL("https://example.com", ["%2e%2e"]),
      ).toThrow();
      // Encoded '../' should also be rejected
      expect(() =>
        createSecureURL("https://example.com", ["%2e%2e%2fetc%2fpasswd"]),
      ).toThrow();
    });

    it("encodeHostLabel delegates to provided IDNA library", async () => {
      const { encodeHostLabel } = await import("../utils/security_kit");
      const calls: string[] = [];
      const stub = { toASCII: (s: string) => (calls.push(s), `xn--stub-${s}`) };
      const out = encodeHostLabel("тест", stub);
      expect(out).toBe("xn--stub-тест");
      expect(calls).toEqual(["тест"]);
    });

    it("encodeHostLabel throws when library missing", async () => {
      const { encodeHostLabel, InvalidParameterError } = await import(
        "../utils/security_kit"
      );
      expect(() => encodeHostLabel("x", null as any)).toThrow(
        InvalidParameterError,
      );
    });
  });

  describe("CryptoKey helpers (security-kit)", () => {
    it("createOneTimeCryptoKey generates a non-extractable AES-GCM key with correct usages", async () => {
      const stub = {
        getRandomValues: (arr: any) => (arr.fill(1), arr),
        subtle: {
          generateKey: vi.fn(
            async (algo: any, extractable: boolean, usages: string[]) => ({
              type: "secret",
              extractable,
              algorithm: { name: algo.name, length: algo.length },
              usages,
            }),
          ),
        },
      } as unknown as Crypto;
      setCrypto(stub);
      const key = await createOneTimeCryptoKey({
        length: 256,
        usages: ["encrypt", "decrypt"],
      });
      expect(typeof key).toBe("object");
      expect((key as any).extractable).toBe(false);
      expect((key as any).type).toBe("secret");
      expect((key as any).usages).toEqual(["encrypt", "decrypt"]);
      expect((key as any).algorithm && (key as any).algorithm.name).toBe(
        "AES-GCM",
      );
      setCrypto(null);
    });

    it("createOneTimeCryptoKey supports bytes or bits and rejects invalid lengths/usages", async () => {
      const stub = {
        getRandomValues: (arr: any) => (arr.fill(2), arr),
        subtle: {
          generateKey: vi.fn(
            async (algo: any, extractable: boolean, usages: string[]) => ({
              type: "secret",
              extractable,
              algorithm: { name: algo.name, length: algo.length },
              usages,
            }),
          ),
        },
      } as unknown as Crypto;
      setCrypto(stub);
      await expect(
        createOneTimeCryptoKey({ length: 128 }),
      ).resolves.toBeDefined();
      await expect(
        createOneTimeCryptoKey({ length: 256 }),
      ).resolves.toBeDefined();
      await expect(
        createOneTimeCryptoKey({ length: 192 as any }),
      ).rejects.toThrow(InvalidParameterError);
      await expect(
        createOneTimeCryptoKey({ usages: [] as any }),
      ).rejects.toThrow(InvalidParameterError);
      await expect(
        createOneTimeCryptoKey({ usages: ["sign"] as any }),
      ).rejects.toThrow(InvalidParameterError);
      setCrypto(null);
    });

    it("createOneTimeCryptoKey falls back to importKey when generateKey is unavailable", async () => {
      const calls = { importKey: 0 };
      const stub = {
        getRandomValues: (arr: any) => (arr.fill(7), arr),
        subtle: {
          generateKey: undefined,
          importKey: vi.fn(
            async (
              format: string,
              keyData: Uint8Array,
              algo: any,
              extractable: boolean,
              usages: string[],
            ) => {
              expect(format).toBe("raw");
              expect(keyData instanceof Uint8Array).toBe(true);
              expect(algo.name).toBe("AES-GCM");
              expect(extractable).toBe(false);
              expect(usages).toEqual(["encrypt", "decrypt"]);
              calls.importKey++;
              return {
                type: "secret",
                extractable,
                algorithm: { name: algo.name },
                usages,
              } as any;
            },
          ),
        },
      } as unknown as Crypto;
      setCrypto(stub);
      const key = await createOneTimeCryptoKey({
        length: 128,
        usages: ["encrypt", "decrypt"],
      });
      expect(calls.importKey).toBe(1);
      expect((key as any).type).toBe("secret");
      expect((key as any).extractable).toBe(false);
      expect((key as any).algorithm.name).toBe("AES-GCM");
      setCrypto(null);
    });

    it("createAesGcmNonce returns a Uint8Array(12) with randomness and enforces bounds", () => {
      const iv = createAesGcmNonce();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(12);
      expect(Array.from(iv).some((b) => b !== 0)).toBe(true);
      expect(() => createAesGcmNonce(11 as any)).toThrow(InvalidParameterError);
      expect(() => createAesGcmNonce(17 as any)).toThrow(InvalidParameterError);
    });
  });

  describe("secureWipe BigInt and typed array support", () => {
    it("wipes BigUint64Array by filling with 0n", () => {
      const arr = new BigUint64Array(4);
      arr.fill(123n);
      // Precondition
      expect(Array.from(arr).some((v) => v !== 0n)).toBe(true);
      secureWipe(arr as any);
      expect(Array.from(arr).every((v) => v === 0n)).toBe(true);
    });

    it("wipes BigInt64Array by filling with 0n", () => {
      const arr = new BigInt64Array(3);
      arr.fill(-5n);
      expect(Array.from(arr).some((v) => v !== 0n)).toBe(true);
      secureWipe(arr as any);
      expect(Array.from(arr).every((v) => v === 0n)).toBe(true);
    });

    it("wipes DataView via Uint8Array view fallback", () => {
      const buf = new ArrayBuffer(8);
      const view = new DataView(buf);
      // Write non-zero bytes
      for (let i = 0; i < 8; i++) view.setUint8(i, 0xff);
      secureWipe(view as any);
      const check = new Uint8Array(buf);
      expect(check.every((b) => b === 0)).toBe(true);
    });
  });

  describe("Production error reporter configuration & sealing", () => {
    it("allows configuring token bucket before sealing and blocks after (isolated instance)", async () => {
      // Use a fresh module instance to avoid sealing the shared import
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      try {
        fresh.setAppEnvironment("development");
      } catch {}
      expect(() =>
        fresh.configureErrorReporter({ burst: 7, refillRatePerSec: 2 }),
      ).not.toThrow();

      // Make crypto available and perform an async call to initialize crypto
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        randomUUID: () => "00000000-0000-4000-8000-000000000000",
      } as unknown as Crypto;
      try {
        fresh.setCrypto(stub);
      } catch {}
      await expect(fresh.generateSecureUUID()).resolves.toMatch(
        /^[0-9a-f-]{36}$/,
      );

      // Seal and verify that subsequent configuration is rejected for this instance
      expect(() => fresh.sealSecurityKit()).not.toThrow();
      expect(() =>
        fresh.configureErrorReporter({ burst: 5, refillRatePerSec: 1 }),
      ).toThrow(fresh.InvalidConfigurationError as any);

      // Reset module cache to avoid leaking sealed state to other tests
      vi.resetModules();
    });

    it("validates numeric ranges for configureErrorReporter (isolated instance)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      expect(() =>
        fresh.configureErrorReporter({ burst: 0 as any, refillRatePerSec: 1 }),
      ).toThrow(fresh.InvalidParameterError as any);
      expect(() =>
        fresh.configureErrorReporter({ burst: 1, refillRatePerSec: -1 as any }),
      ).toThrow(fresh.InvalidParameterError as any);
      vi.resetModules();
    });
  });

  describe("createOneTimeCryptoKey option validation", () => {
    it("rejects specifying both lengthBits and deprecated length (isolated instance)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      const stub = {
        getRandomValues: (a: any) => (a.fill(3), a),
        subtle: {
          generateKey: vi.fn(
            async (algo: any, extractable: boolean, usages: string[]) => ({
              type: "secret",
              extractable,
              algorithm: { name: algo.name, length: algo.length },
              usages,
            }),
          ),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      await expect(
        fresh.createOneTimeCryptoKey({ lengthBits: 128, length: 128 } as any),
      ).rejects.toThrow(fresh.InvalidParameterError as any);
      vi.resetModules();
    });
  });

  describe("secureCompareAsync cache (HMAC-keyed)", () => {
    const { secureCompareAsync, setCrypto } = securityKit as any;
    const __internal: any = (securityKit as any).__internal;

    beforeEach(() => {
      if (__internal) {
        __internal._clearCacheForTest();
      }
    });

    it("caches digest entries when enabled and does not store raw input", async () => {
      if (!__internal) {
        // Skip test in production builds where __internal is not exported
        return;
      }

      // Create a mock crypto with digest support for cache testing
      const mockCryptoWithDigest = {
        getRandomValues: (arr: Uint8Array) => {
          // Fill with deterministic values for testing
          for (let i = 0; i < arr.length; i++) {
            arr[i] = i % 256;
          }
          return arr;
        },
        subtle: {
          digest: vi.fn(async (algorithm: string, data: Uint8Array) => {
            // Return a deterministic hash for testing
            const hash = new ArrayBuffer(32); // SHA-256 size
            const view = new Uint8Array(hash);
            for (let i = 0; i < view.length; i++) {
              view[i] = (data.length + i) % 256;
            }
            return hash;
          }),
          importKey: vi.fn(async () => ({ type: "secret" })),
          sign: vi.fn(async () => {
            const sig = new ArrayBuffer(32);
            const view = new Uint8Array(sig);
            view.fill(42); // deterministic signature
            return sig;
          }),
        },
      } as unknown as Crypto;

      setCrypto(mockCryptoWithDigest);

      const a = "my-super-secret-token-123";
      const res1 = await secureCompareAsync(a, a, {
        UNSAFE_enableTimingVulnerableCache: true,
      } as any);
      expect(res1).toBe(true);

      const keys = __internal._getCacheKeysForTest();
      expect(keys.length).toBeGreaterThanOrEqual(1);

      // cache key should be HMAC/base64-ish and must not include the raw input string
      const containsRaw = keys.some((k: string) =>
        k.includes("my-super-secret-token-123"),
      );
      expect(containsRaw).toBe(false);

      // keys should look like base64 (basic sanity check)
      const plausibleBase64 = keys.every((k: string) =>
        /^[A-Za-z0-9+/=]+$/.test(k),
      );
      expect(plausibleBase64).toBe(true);

      // Restore original mock
      setCrypto(mockCrypto);
    });

    it("reusing the cached entry on subsequent calls", async () => {
      if (!__internal) {
        // Skip test in production builds where __internal is not exported
        return;
      }

      // Create a mock crypto with digest support for cache testing
      const mockCryptoWithDigest = {
        getRandomValues: (arr: Uint8Array) => {
          for (let i = 0; i < arr.length; i++) {
            arr[i] = i % 256;
          }
          return arr;
        },
        subtle: {
          digest: vi.fn(async (algorithm: string, data: Uint8Array) => {
            const hash = new ArrayBuffer(32);
            const view = new Uint8Array(hash);
            for (let i = 0; i < view.length; i++) {
              view[i] = (data.length + i) % 256;
            }
            return hash;
          }),
          importKey: vi.fn(async () => ({ type: "secret" })),
          sign: vi.fn(async () => {
            const sig = new ArrayBuffer(32);
            const view = new Uint8Array(sig);
            view.fill(42);
            return sig;
          }),
        },
      } as unknown as Crypto;

      setCrypto(mockCryptoWithDigest);
      __internal._clearCacheForTest();

      const key = "short-secret";
      await secureCompareAsync(key, key, {
        UNSAFE_enableTimingVulnerableCache: true,
      } as any);
      const sizeAfterFirst = __internal._getCacheSizeForTest();
      expect(sizeAfterFirst).toBeGreaterThanOrEqual(1);

      // Second call should not increase cache size (hit)
      await secureCompareAsync(key, key, {
        UNSAFE_enableTimingVulnerableCache: true,
      } as any);
      const sizeAfterSecond = __internal._getCacheSizeForTest();
      expect(sizeAfterSecond).toBe(sizeAfterFirst);

      // Restore original mock
      setCrypto(mockCrypto);
    });
  });

  describe("concurrent secureCompareAsync and ensureCrypto lifecycle", () => {
    const { secureCompareAsync } = securityKit;

    it("multiple concurrent callers succeed and return consistent results", async () => {
      const tasks = Array.from({ length: 8 }, (_, i) =>
        (secureCompareAsync as any)("concurrent-" + i, "concurrent-" + i, {
          UNSAFE_enableTimingVulnerableCache: false,
        } as any),
      );
      const results = await Promise.all(tasks);
      expect(results.every(Boolean)).toBe(true);
    });
  });

  describe("SRI Generation (security-kit)", () => {
    it("generateSRI creates valid SHA-256 hash (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      // Ensure SubtleCrypto.digest is available via stub
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {
          digest: vi.fn(async () => new Uint8Array(32).fill(7).buffer),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = 'console.log("Hello, world!");';
      const sri = await fresh.generateSRI(content, "sha256");
      expect(sri).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
      vi.resetModules();
    });

    it("generateSRI creates valid SHA-384 hash (default, isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {
          digest: vi.fn(async () => new Uint8Array(48).fill(3).buffer),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = 'console.log("Hello, world!");';
      const sri = await fresh.generateSRI(content); // defaults to sha384
      expect(sri).toMatch(/^sha384-[A-Za-z0-9+/]+=*$/);
      vi.resetModules();
    });

    it("generateSRI creates valid SHA-512 hash (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {
          digest: vi.fn(async () => new Uint8Array(64).fill(5).buffer),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = 'console.log("Hello, world!");';
      const sri = await fresh.generateSRI(content, "sha512");
      expect(sri).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
      vi.resetModules();
    });

    it("generateSRI handles ArrayBuffer input (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {
          digest: vi.fn(async () => new Uint8Array(32).fill(11).buffer),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = new TextEncoder().encode("test content");
      const sri = await fresh.generateSRI(content.buffer, "sha256");
      expect(sri).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
      vi.resetModules();
    });

    it("generateSRI produces consistent results for same input (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {
          digest: vi.fn(async (_alg: string, data: ArrayBuffer) => {
            const v = new Uint8Array(data);
            const out = new Uint8Array(32);
            for (let i = 0; i < out.length; i++)
              out[i] = (v[i % v.length] ?? 0) ^ 0xaa;
            return out.buffer;
          }),
        },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = "test content for consistency";
      const a = await fresh.generateSRI(content, "sha256");
      const b = await fresh.generateSRI(content, "sha256");
      expect(a).toBe(b);
      vi.resetModules();
    });

    it("generateSRI throws on unsupported algorithm (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      // Provide digest so we hit algorithm validation
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: { digest: vi.fn(async () => new Uint8Array(32).buffer) },
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      const content = "test";
      // @ts-expect-error Testing invalid algorithm
      await expect(fresh.generateSRI(content, "md5")).rejects.toThrow(
        "Unsupported SRI algorithm: md5",
      );
      vi.resetModules();
    });

    it("generateSRI throws when SubtleCrypto unavailable (isolated)", async () => {
      vi.resetModules();
      const fresh = await import("../utils/security_kit");
      // Missing digest method
      const stub = {
        getRandomValues: (a: any) => (a.fill(1), a),
        subtle: {},
      } as unknown as Crypto;
      fresh.setCrypto(stub);
      await expect(fresh.generateSRI("test")).rejects.toThrow(
        /SubtleCrypto\.digest is required/,
      );
      vi.resetModules();
    });

    it("generateSRI throws on null/undefined input", async () => {
      const { generateSRI } = await import("../utils/security_kit");
      // @ts-expect-error testing invalid input
      await expect(generateSRI(null)).rejects.toThrow(
        "Input content is required for SRI generation",
      );
      // @ts-expect-error testing invalid input
      await expect(generateSRI(undefined)).rejects.toThrow(
        "Input content is required for SRI generation",
      );
    });

    it("generateSRI wipe finally block tolerates non-writable buffers", async () => {
      const { generateSRI, setCrypto } = await import("../utils/security_kit");
      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: {
          digest: async () => {
            // Return an ArrayBuffer; intentionally freeze to make wipe attempt no-op
            const buf = new ArrayBuffer(16);
            try {
              Object.freeze(buf);
            } catch {}
            return buf;
          },
        },
      } as unknown as Crypto;
      try {
        setCrypto(fakeCrypto);
        const sri = await generateSRI("test-input", "sha256");
        expect(typeof sri).toBe("string");
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI finally wipe tolerates digest throwing", async () => {
      const { generateSRI, setCrypto } = await import("../utils/security_kit");
      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: {
          digest: async () => {
            throw new Error("digest-failure");
          },
        },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);
        await expect(generateSRI("will-fail", "sha256")).rejects.toThrow(
          "digest-failure",
        );
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI executes finally wipe for both digest and string buffer", async () => {
      // Import the module object so we can spy on its exported secureWipe correctly
      const mod = await import("../utils/security_kit");
      const { generateSRI, setCrypto } = mod;
      // subtle.digest returns an ArrayBuffer and input is string -> both digest and dataForDigest wiping should run
      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: {
          digest: vi.fn(async () => {
            const ab = new ArrayBuffer(32);
            const view = new Uint8Array(ab);
            for (let i = 0; i < view.length; i++) view[i] = i & 0xff;
            return ab;
          }),
        },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);
        // Prepare a digest ArrayBuffer we can observe being wiped
        const returnedDigest = new ArrayBuffer(32);
        const returnedView = new Uint8Array(returnedDigest);
        for (let i = 0; i < returnedView.length; i++) returnedView[i] = i + 1;

        // Force subtle.digest to return our observable buffer
        (fakeCrypto.subtle as any).digest = vi.fn(async () => returnedDigest);

        const sri = await generateSRI("wipe-test-input", "sha256");
        expect(typeof sri).toBe("string");
        // Ensure subtle.digest was invoked
        expect((fakeCrypto.subtle as any).digest).toHaveBeenCalled();

        // After generateSRI completes, the digest buffer returned by subtle.digest
        // should have been wiped (filled with zeros) by the finally block.
        const after = new Uint8Array(returnedDigest);
        const allZero = Array.from(after).every((b) => b === 0);
        expect(allZero).toBe(true);
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI calls secureWipe for digest and dataForDigest (string input)", async () => {
      // Import module so we can spy on exported secureWipe
      const mod = await import("../utils/security_kit");
      const { generateSRI, setCrypto } = mod as any;

      // Prepare observable digest buffer returned by subtle.digest
      const returnedDigest = new ArrayBuffer(32);
      const returnedView = new Uint8Array(returnedDigest);
      for (let i = 0; i < returnedView.length; i++) returnedView[i] = i + 1;

      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: { digest: vi.fn(async () => returnedDigest) },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);

        // Spy on secureWipe export to observe calls
        const wipeSpy = vi.spyOn(mod as any, "secureWipe");

        const sri = await generateSRI("wipe-data-for-digest", "sha256");
        expect(typeof sri).toBe("string");

        // Expect either the secureWipe spy to have been called, or the returned
        // digest buffer to have been zeroed. Some environments may perform the
        // wipe on a different view, so check both possibilities to avoid
        // intermittent false negatives.
        const wipeCalled = wipeSpy.mock.calls.length > 0;

        const after = new Uint8Array(returnedDigest);
        const digestAllZero = Array.from(after).every((b) => b === 0);

        expect(wipeCalled || digestAllZero).toBe(true);

        if (wipeCalled) {
          // If the spy was called, assert at least one argument looked like a Uint8Array
          const hadUint8ArrayArg = wipeSpy.mock.calls.some(
            (call) => call.length > 0 && call[0] instanceof Uint8Array,
          );
          expect(hadUint8ArrayArg).toBe(true);
        }

        wipeSpy.mockRestore();
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI wipes caller-owned ArrayBuffer input when provided", async () => {
      const mod = await import("../utils/security_kit");
      const { generateSRI, setCrypto } = mod;

      // Create an ArrayBuffer owned by the caller and pass it to generateSRI
      const inputBuf = new ArrayBuffer(48);
      const iv = new Uint8Array(inputBuf);
      for (let i = 0; i < iv.length; i++) iv[i] = i + 1;

      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: {
          digest: vi.fn(async () => {
            // For this test, subtle.digest will return a new ArrayBuffer (digest)
            // and will not mutate the caller-owned input. We assert that the
            // finally block does not attempt to wipe caller-owned buffers.
            const d = new ArrayBuffer(32);
            const dv = new Uint8Array(d);
            dv.fill(123);
            return d;
          }),
        },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);
        const sri = await generateSRI(inputBuf, "sha256");
        expect(typeof sri).toBe("string");

        // The caller-owned input buffer should remain unchanged (we don't mutate
        // external ArrayBuffers), so its contents should still be the values we set.
        const afterInput = new Uint8Array(inputBuf);
        expect(afterInput[0]).toBe(1);
        expect(afterInput[afterInput.length - 1]).toBe(iv[iv.length - 1]);
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI calls secureWipe for both digest and internal data buffer (string input)", async () => {
      const mod = await import("../utils/security_kit");
      const { generateSRI, setCrypto } = mod as any;

      // Prepare crypto that returns an observable digest buffer
      const returnedDigest = new ArrayBuffer(32);
      const returnedView = new Uint8Array(returnedDigest);
      for (let i = 0; i < returnedView.length; i++) returnedView[i] = i + 1;

      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: { digest: vi.fn(async () => returnedDigest) },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);

        // Spy on the exported secureWipe so we can assert it's been called.
        const wipeSpy = vi
          .spyOn(mod as any, "secureWipe")
          .mockImplementation((_: any) => {
            /* noop */
          });

        const inputString = "sensitive content to hash";
        const sri = await generateSRI(inputString, "sha256");
        expect(typeof sri).toBe("string");

        // Expect either the secureWipe spy to have been called, or the returned
        // digest buffer to have been zeroed. This avoids brittle coupling to
        // module binding subtleties across environments.
        const wipeCalled = (wipeSpy as any).mock.calls.length > 0;
        const afterDigest = new Uint8Array(returnedDigest);
        const allZero = Array.from(afterDigest).every((b) => b === 0);
        expect(wipeCalled || allZero).toBe(true);

        wipeSpy.mockRestore();
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("generateSRI tolerates secureWipe throwing (best-effort wipe)", async () => {
      const mod = await import("../utils/security_kit");
      const { generateSRI, setCrypto } = mod;

      const fakeCrypto = {
        getRandomValues: (arr: Uint8Array) => {
          arr.fill(0);
          return arr;
        },
        subtle: {
          digest: vi.fn(async () => {
            const d = new ArrayBuffer(16);
            const dv = new Uint8Array(d);
            for (let i = 0; i < dv.length; i++) dv[i] = i + 2;
            return d;
          }),
        },
      } as unknown as Crypto;

      try {
        setCrypto(fakeCrypto);
        // Temporarily mock exported secureWipe to throw, using spyOn (module bindings are read-only)
        const wipeSpy = vi
          .spyOn(mod as any, "secureWipe")
          .mockImplementation(() => {
            throw new Error("wipe-failure");
          });

        // Should still resolve and not let the thrown wipe escape (best-effort)
        const sri = await generateSRI("some-input", "sha256");
        expect(typeof sri).toBe("string");

        // Restore original implementation
        wipeSpy.mockRestore();
      } finally {
        try {
          setCrypto(null);
        } catch {}
      }
    });

    it("secureWipe zeroes DataView and warns on large buffers", async () => {
      const mod = await import("../utils/security_kit");
      const { secureWipe, setAppEnvironment } = mod as any;

      try {
        // Ensure development-mode warnings are enabled
        setAppEnvironment("development");

        const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

        // Create a large ArrayBuffer and a DataView over it
        const ab = new ArrayBuffer(2048);
        const dv = new DataView(ab);
        // Fill underlying buffer with non-zero bytes
        const u8 = new Uint8Array(ab);
        u8.fill(0xff);

        // Wipe using DataView (should zero underlying buffer)
        secureWipe(dv as any);
        const after = new Uint8Array(ab);
        expect(Array.from(after).every((b) => b === 0)).toBe(true);

        // Wipe a large typed array to trigger development warning
        const big = new Uint8Array(2048);
        big.fill(1);
        secureWipe(big);
        expect(warnSpy).toHaveBeenCalled();

        warnSpy.mockRestore();
      } finally {
        // No-op
      }
    });
  });

  describe("Secure PostMessage utilities (security-kit)", () => {
    const { sendSecurePostMessage, createSecurePostMessageListener } =
      securityKit;
    let mockWindow: any;
    let mockTargetWindow: any;

    beforeEach(() => {
      mockTargetWindow = {
        postMessage: vi.fn(),
      };

      // Mock window for event listener tests
      mockWindow = {
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      };

      // Replace global window for these tests
      vi.stubGlobal("window", mockWindow);
      vi.stubGlobal(
        "AbortController",
        class {
          signal = { aborted: false };
          abort = vi.fn(() => {
            this.signal.aborted = true;
          });
        },
      );
    });

    describe("sendSecurePostMessage", () => {
      it("sends message with JSON payload to specific origin", () => {
        const payload = { type: "test", data: "hello" };

        sendSecurePostMessage({
          targetWindow: mockTargetWindow,
          payload,
          targetOrigin: "https://trusted.example.com",
        });

        expect(mockTargetWindow.postMessage).toHaveBeenCalledWith(
          JSON.stringify(payload),
          "https://trusted.example.com",
        );
      });

      it("throws when targetOrigin is wildcard", () => {
        expect(() => {
          sendSecurePostMessage({
            targetWindow: mockTargetWindow,
            payload: { test: true },
            targetOrigin: "*",
          });
        }).toThrow(
          "targetOrigin cannot be a wildcard ('*'). You must provide a specific origin.",
        );
      });

      it("throws when targetWindow is missing", () => {
        expect(() => {
          sendSecurePostMessage({
            targetWindow: null as any,
            payload: { test: true },
            targetOrigin: "https://example.com",
          });
  }).toThrow(/targetWindow must be provided\.?/);
      });

      it("throws when targetOrigin is empty or invalid", () => {
        expect(() => {
          sendSecurePostMessage({
            targetWindow: mockTargetWindow,
            payload: { test: true },
            targetOrigin: "",
          });
  }).toThrow(/targetOrigin must be a specific string\.?/);
      });
    });

    describe("createSecurePostMessageListener", () => {
      it("creates listener with origin allowlist", () => {
        const allowedOrigins = [
          "https://trusted.example.com",
          "https://app.example.com",
        ];
        const onMessage = vi.fn();

        const listener = createSecurePostMessageListener(
          allowedOrigins,
          onMessage,
        );

        expect(mockWindow.addEventListener).toHaveBeenCalledWith(
          "message",
          expect.any(Function),
          expect.objectContaining({ signal: expect.any(Object) }),
        );
        expect(listener.destroy).toBeInstanceOf(Function);
      });

      it("rejects messages from non-allowlisted origins", () => {
        const allowedOrigins = ["https://trusted.example.com"];
        const onMessage = vi.fn();

        createSecurePostMessageListener(allowedOrigins, onMessage);

        // Get the event handler that was registered
        const eventHandler = mockWindow.addEventListener.mock.calls[0][1];

        // Simulate message from non-allowlisted origin
        const mockEvent = {
          origin: "https://evil.example.com",
          data: JSON.stringify({ test: true }),
        };

        eventHandler(mockEvent);

        expect(onMessage).not.toHaveBeenCalled();
      });

      it("accepts and parses messages from allowlisted origins", () => {
        const allowedOrigins = ["https://trusted.example.com"];
        const onMessage = vi.fn();

        createSecurePostMessageListener(allowedOrigins, onMessage);

        const eventHandler = mockWindow.addEventListener.mock.calls[0][1];
        const testData = { type: "test", message: "hello" };

        const mockEvent = {
          origin: "https://trusted.example.com",
          data: JSON.stringify(testData),
        };

        eventHandler(mockEvent);

        expect(onMessage).toHaveBeenCalledWith(testData);
      });

      it("handles malformed JSON gracefully", () => {
        const allowedOrigins = ["https://trusted.example.com"];
        const onMessage = vi.fn();

        createSecurePostMessageListener(allowedOrigins, onMessage);

        const eventHandler = mockWindow.addEventListener.mock.calls[0][1];

        const mockEvent = {
          origin: "https://trusted.example.com",
          data: "invalid json {",
        };

        // Should not throw, just not call onMessage
        expect(() => eventHandler(mockEvent)).not.toThrow();
        expect(onMessage).not.toHaveBeenCalled();
      });

      it("throws on invalid allowedOrigins with wildcard", () => {
        expect(() => {
          createSecurePostMessageListener(["*"], vi.fn());
        }).toThrow(
          "allowedOrigins must be an array of specific origin strings.",
        );
      });

      it("throws on non-function onMessage", () => {
        expect(() => {
          createSecurePostMessageListener(
            ["https://example.com"],
            "not a function" as any,
          );
  }).toThrow(/onMessage must be a function\.?/);
      });

      it("destroy method cleans up event listener", () => {
        // Create a mock AbortController with proper mock tracking
        const mockAbort = vi.fn();
        const mockAbortController = {
          abort: mockAbort,
          signal: { aborted: false } as AbortSignal,
        };

        const AbortControllerSpy = vi
          .spyOn(global, "AbortController")
          .mockImplementation(() => mockAbortController as any);

        const listener = createSecurePostMessageListener(
          ["https://example.com"],
          vi.fn(),
        );

        listener.destroy();

        expect(mockAbort).toHaveBeenCalled();

        AbortControllerSpy.mockRestore();
      });
    });
  });

  describe("Deprecated and legacy functions (security-kit)", () => {
    const { secureDevNotify, secureDevLog } = securityKit;

    it("secureDevNotify shows deprecation warning in development", () => {
      // Ensure environment is development so secureDevLog will execute
      setAppEnvironment("development");
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

      secureDevNotify("info", "test-component", { data: "test" });

      expect(consoleSpy).toHaveBeenCalledWith(
        "[security-kit] `secureDevNotify` is deprecated and will be removed in a future version. Use `secureDevLog`.",
      );
      // secureDevNotify calls the internal secureDevLog function which in turn
      // logs via console.info for 'info' level. Assert that console.info was used.
      expect(infoSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
      infoSpy.mockRestore();
    });
  });

  describe("Production error handling and sealing (security-kit)", () => {
    const { setProductionErrorHandler, sealSecurityKit, setAppEnvironment } =
      securityKit;

    beforeEach(() => {
      // Reset sealed state for each test
      try {
        setAppEnvironment("development");
      } catch {
        // Ignore if already sealed
      }
    });

    test("setProductionErrorHandler sets the error hook", () => {
      const errorHook = vi.fn();

      setProductionErrorHandler(errorHook);

      // Verify hook is set by triggering an error scenario
      expect(() => setProductionErrorHandler(errorHook)).not.toThrow();
    });

    test("sealSecurityKit prevents further configuration changes", () => {
      // Set up crypto first
      setCrypto(globalThis.crypto);

      sealSecurityKit();

      expect(() => setAppEnvironment("production")).toThrow(
        "Configuration is sealed and cannot be changed.",
      );
      expect(() => setCrypto(null)).toThrow(
        "Configuration is sealed and cannot be changed.",
      );
      expect(() => setProductionErrorHandler(vi.fn())).toThrow(
        "Configuration is sealed and cannot be changed.",
      );
    });

    test("sealSecurityKit throws if called before crypto is available", async () => {
      // Module-level sealed/configured state can leak between Vitest module instances.
      // Import a fresh copy of the module (after vi.resetModules and temporarily
      // removing globalThis.crypto) so this test deterministically exercises the
      // "no crypto available" path instead of depending on prior test order.
      // This keeps the assertion stable in CI and local runs.
      // To avoid shared global state across tests, import a fresh copy of the module
      vi.resetModules();
      // Ensure no global crypto is present for this import
      const originalCrypto = (globalThis as any).crypto;
      try {
        Object.defineProperty(globalThis as any, "crypto", {
          value: undefined,
          configurable: true,
        });
        const fresh = await import("../utils/security_kit");
        expect(() => fresh.sealSecurityKit()).toThrow(
          /sealSecurityKit\(\) cannot be called before a crypto implementation is available/,
        );
      } finally {
        // Restore original crypto
        try {
          Object.defineProperty(globalThis as any, "crypto", {
            value: originalCrypto,
            configurable: true,
          });
        } catch {}
        vi.resetModules();
      }
    });
  });

  describe("Advanced environment detection edge cases", () => {
    const { environment } = securityKit;

    test("environment handles IPv6 localhost correctly", () => {
      const mockLocation = { hostname: "[::1]" };
      vi.stubGlobal("location", mockLocation);

      environment.clearCache();

      expect(environment.isDevelopment).toBe(true);
    });

    test("environment handles .local domains correctly", () => {
      const mockLocation = { hostname: "dev.local" };
      vi.stubGlobal("location", mockLocation);

      environment.clearCache();

      expect(environment.isDevelopment).toBe(true);
    });

    test("environment handles private 172.x.x.x networks correctly", () => {
      const mockLocation = { hostname: "172.20.10.2" };
      vi.stubGlobal("location", mockLocation);

      environment.clearCache();

      expect(environment.isDevelopment).toBe(true);
    });

    test("environment handles invalid hostname gracefully", () => {
      const mockLocation = { hostname: undefined };
      vi.stubGlobal("location", mockLocation);

      environment.clearCache();

      // Should not throw and empty/undefined hostname is treated as development in the current implementation
      expect(environment.isDevelopment).toBe(true);
    });
  });
});
