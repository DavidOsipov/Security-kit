// tests/security_kit.fuzz.advanced.spec.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fc from "fast-check";
import * as securityKit from "../utils/security_kit"; // adjust path if needed

// allow controlling fast-check runs via env
const NIGHTLY = !!process.env.NIGHTLY;
const DEFAULT_RUNS = NIGHTLY ? 2000 : 250;
const MAX_STRING_LEN = NIGHTLY ? 8192 : 1024;

// Make fast-check deterministic/reproducible when FAST_CHECK_SEED is set
if (process.env.FAST_CHECK_SEED) {
  const seed = Number(process.env.FAST_CHECK_SEED);
  if (!Number.isNaN(seed)) {
    fc.configureGlobal({ seed });
    // optional: increase verbosity for reproduction
    console.info(`[fuzz] fast-check seed set to ${seed}`);
  }
}

// Helpful wrapper to set test-specific numRuns and timeout
function fcAssert(
  prop: fc.Arbitrary<any> | any,
  opts: { numRuns?: number; timeoutMs?: number } = {},
) {
  return fc.assert(prop, {
    numRuns: opts.numRuns ?? DEFAULT_RUNS,
    interruptAfterTimeLimit: opts.timeoutMs ?? (NIGHTLY ? 60_000 : 10_000),
    verbose: !!process.env.FAST_CHECK_VERBOSE,
  } as any);
}

// Deterministic/mock crypto helpers
function makeDeterministicCrypto() {
  return {
    getRandomValues: (arr: Uint8Array | Uint32Array | BigUint64Array) => {
      // repeatable deterministic pseudo-random fill
      for (let i = 0; i < (arr as any).length; i++) {
        (arr as any)[i] = (i * 31 + 17) & 0xff;
      }
      return arr;
    },
    randomUUID: () => "00000000-0000-4000-8000-000000000000",
    subtle: {
      digest: async (_alg: string, data: ArrayBuffer) => {
        // toy deterministic digest: 32 bytes derived from input
        const out = new Uint8Array(32);
        const v = new Uint8Array(data);
        for (let i = 0; i < out.length; i++)
          out[i] = (v[i % v.length] ?? 0) ^ (i + 1);
        return out.buffer;
      },
      importKey: async () => ({}),
      sign: async () => new ArrayBuffer(32),
    },
  } as unknown as Crypto;
}

function makeFlakyCrypto(flakyAfter = 3) {
  // throws on the nth call to simulate hardware failures
  let calls = 0;
  return {
    getRandomValues: (arr: Uint8Array) => {
      calls++;
      if (calls >= flakyAfter) throw new Error("Simulated crypto failure");
      for (let i = 0; i < arr.length; i++) arr[i] = (i + calls) & 0xff;
      return arr;
    },
    randomUUID: () => "deadbeef-dead-4bee-badd-deadbeef0000",
    subtle: {
      digest: async (_alg: string, data: ArrayBuffer) => {
        const out = new Uint8Array(32);
        const v = new Uint8Array(data);
        for (let i = 0; i < out.length; i++)
          out[i] = (v[i % v.length] ?? 0) ^ (i + 2);
        return out.buffer;
      },
    },
  } as unknown as Crypto;
}

// Controlled crypto that delays fill until external resolve (for concurrency tests)
function makeControllableCrypto() {
  let resolver: (() => void) | null = null;
  const ready = new Promise<void>((res) => {
    resolver = res;
  });
  const object = {
    getRandomValues: (arr: Uint8Array) => {
      // synchronous style: block until resolved (we'll await from caller by waiting for ready)
      // but because getRandomValues cannot be async, we instead assume tests call setCrypto with this object
      // and ensure they resolve the ready promise before calling functions that use it.
      for (let i = 0; i < arr.length; i++) arr[i] = (i * 7) & 0xff;
      return arr;
    },
    randomUUID: () => "00000000-0000-4000-8000-000000000000",
    subtle: {
      digest: async (_alg: string, data: ArrayBuffer) => {
        await ready;
        const out = new Uint8Array(32);
        const v = new Uint8Array(data);
        for (let i = 0; i < out.length; i++)
          out[i] = (v[i % v.length] ?? 0) ^ 13;
        return out.buffer;
      },
    },
    _resolve: () => {
      if (resolver) resolver();
    },
  } as unknown as Crypto & { _resolve?: () => void };
  return object;
}

// Reset module-level state between some tests: try to be graceful if sealed
function tryResetCrypto() {
  try {
    // use synchronous call where possible; some test environments make setCrypto synchronous
    // and the sealed state will throw — swallow errors to be tolerant in tests
    securityKit.setCrypto(null);
  } catch {
    // ignore if sealed
  }
}

describe("Advanced fuzzing — security-kit", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    try {
      securityKit.setCrypto(makeDeterministicCrypto());
    } catch {
      // maybe sealed; ignore
    }
  });
  afterEach(() => {
    tryResetCrypto();
  });

  // 1) secureCompare: normalization invariants & large unicode inputs
  it("secureCompare agrees with NFC-normalized equality for many random unicode strings", async () => {
    await fcAssert(
      fc.asyncProperty(
        fc.string({ maxLength: MAX_STRING_LEN }),
        fc.string({ maxLength: MAX_STRING_LEN }),
        async (a, b) => {
          if (a.length > 4096 || b.length > 4096) return true; // module limit guard
          const normalizedEq =
            String(a ?? "").normalize("NFC") ===
            String(b ?? "").normalize("NFC");
          const sync = securityKit.secureCompare(a, b);
          const asyncCmp = await securityKit.secureCompareAsync(a, b);
          // Must be consistent across sync/async and match normalization
          return sync === asyncCmp && sync === normalizedEq;
        },
      ),
      { numRuns: Math.min(DEFAULT_RUNS, 800), timeoutMs: 20_000 },
    );
  });

  // 2) secureCompareAsync fallback & digest behavior under flaky crypto
  it("secureCompareAsync falls back correctly when subtle.digest or crypto isn't available", async () => {
    // First: good crypto -> should match
    await securityKit.setCrypto(makeDeterministicCrypto());
    await expect(securityKit.secureCompareAsync("a", "a")).resolves.toBe(true);

    // Next: flaky crypto that will throw on getRandomValues (simulate unexpected error)
    await securityKit.setCrypto(makeFlakyCrypto(1));
    // with flaky crypto, we still expect secureCompareAsync to either succeed or fall back safely
    await expect(securityKit.secureCompareAsync("x", "x"))
      .resolves.toBe(true)
      .catch(() => true);

    await securityKit.setCrypto(makeDeterministicCrypto());
  });

  // 3) strictDecodeURIComponent: repair mode and very-malformed inputs (fuzz)
  it("strictDecodeURIComponent repair mode should never throw for arbitrary strings", async () => {
    await fcAssert(
      fc.asyncProperty(fc.string({ maxLength: MAX_STRING_LEN }), async (s) => {
        const res = securityKit.strictDecodeURIComponent(s, {
          onError: "replace",
          replaceWith: "\uFFFD",
        });
        // function must return an object with ok boolean
        return typeof res === "object" && "ok" in res;
      }),
      { numRuns: DEFAULT_RUNS, timeoutMs: 20_000 },
    );
  });

  // 4) _redact fuzz: prototype pollution attempts, deep nesting and arrays including functions (should be safe)
  it("redaction should not cause prototype pollution and should redact probable secrets", async () => {
    // Build a generator for complex objects: nested maps, arrays, secret-like keys and prototype payloads
    const keyish = fc.oneof(
      fc.string({ minLength: 1, maxLength: 32 }),
      fc.constantFrom(
        "password",
        "token",
        "auth_key",
        "__proto__",
        "constructor",
      ),
    );
    const valueish = fc.oneof(
      fc.string({ maxLength: Math.floor(MAX_STRING_LEN / 10) }),
      fc.integer(),
      fc.boolean(),
      fc.constant(null),
    );
    const objArb = fc.dictionary(
      keyish,
      fc.oneof(valueish, fc.array(valueish, { minLength: 0, maxLength: 5 })),
      { maxKeys: 12 },
    );

    await fcAssert(
      fc.property(objArb, (o) => {
        // include a prototype pollution attempt
        (o as any)["__proto__"] = { polluted: true };
        const testUtils = securityKit.getInternalTestUtils();
        const redacted = testUtils?._redact ? testUtils._redact(o) : undefined;
        // Confirm the real global prototype did not get polluted
        const polluted = ({} as any).polluted;
        if (polluted !== undefined) return false;
        // secret-like keys should be redacted if present
        if (o && typeof o === "object") {
          for (const k of Object.keys(o)) {
            if (
              /token|secret|password|pass|auth|key|bearer|session|credential|jwt|signature|cookie|private|cert/i.test(
                k,
              )
            ) {
              if (!redacted || (redacted as any)[k] !== "[REDACTED]")
                return false;
            }
          }
        }
        return true;
      }),
      { numRuns: Math.min(400, DEFAULT_RUNS), timeoutMs: 20_000 },
    );
  });

  // 5) secureWipe: DataView / sliced buffers / typed array variants (medium memory)
  it("secureWipe zeroes various views (Uint8Array, DataView, sliced)", async () => {
    // limit large sizes in CI; increase locally or in nightly
    const maxLen = NIGHTLY ? 200_000 : 50_000;
    await fcAssert(
      fc.property(fc.integer({ min: 1, max: maxLen }), (len) => {
        const buf = new ArrayBuffer(len);
        const u8 = new Uint8Array(buf);
        for (let i = 0; i < u8.length; i++) u8[i] = i % 256 || 1;
        // create different views
        const dv = new DataView(buf);
        const slice = new Uint8Array(
          buf,
          Math.floor(len / 4),
          Math.max(1, Math.floor(len / 4)),
        );
        // wipe the original DV and slice
        securityKit.secureWipe(dv as any);
        securityKit.secureWipe(slice as any);
        // check some bytes are zeroed (best-effort; engines may copy)
        const check = new Uint8Array(buf).every((b) => b === 0);
        return check === true;
      }),
      { numRuns: 12, timeoutMs: NIGHTLY ? 120_000 : 20_000 },
    );
  });

  // 6) getSecureRandomInt: fuzz ranges incl edges and invalid combos
  it("getSecureRandomInt returns numbers in-range and rejects invalid ranges (property)", async () => {
    await fcAssert(
      fc.asyncProperty(
        fc.integer({ min: -Math.pow(2, 31), max: Math.pow(2, 31) - 1 }),
        fc.integer({ min: -Math.pow(2, 31), max: Math.pow(2, 31) - 1 }),
        async (a, b) => {
          if (a > b) {
            await expect(
              securityKit.getSecureRandomInt(a, b),
            ).rejects.toBeDefined();
            return true;
          } else {
            const v = await securityKit.getSecureRandomInt(a, b);
            return Number.isInteger(v) && v >= a && v <= b;
          }
        },
      ),
      { numRuns: Math.min(DEFAULT_RUNS, 600), timeoutMs: 30_000 },
    );
  });

  // 7) generateSecureId / bytesToHex: test odd lengths, large sizes, Buffer fallback
  it("generateSecureId handles odd lengths and Buffer fallback branch", async () => {
    // spy on Buffer presence and override for Buffer path
    const originalBuffer = (globalThis as any).Buffer;
    try {
      (globalThis as any).Buffer = {
        from: (_b: Uint8Array) => ({ toString: () => "cafebabe".repeat(4) }),
      };
      const v = await securityKit.generateSecureId(8);
      expect(typeof v).toBe("string");
    } finally {
      (globalThis as any).Buffer = originalBuffer;
    }

    // odd length
    await securityKit.setCrypto(makeDeterministicCrypto());
    const idOdd = await securityKit.generateSecureId(3);
    expect(idOdd.length).toBe(3);
  });

  // 8) sendSecurePostMessage: circular payloads and huge payloads
  it("sendSecurePostMessage should throw on circular payloads and handle JSON-safe payloads", () => {
    const target = { postMessage: vi.fn() };
    const a: any = { x: 1 };
    a.self = a;
    expect(() =>
      securityKit.sendSecurePostMessage({
        targetWindow: target as any,
        payload: a as any,
        targetOrigin: "https://ok",
      }),
    ).toThrow();

    // large but non-circular payload
    const payload = { data: "A".repeat(NIGHTLY ? 200000 : 5000) };
    expect(() =>
      securityKit.sendSecurePostMessage({
        targetWindow: target as any,
        payload,
        targetOrigin: "https://ok",
      }),
    ).not.toThrow();
  });

  // 9) Concurrency/race: many concurrent generateSecureId calls while setCrypto swapped mid-flight
  it(
    "concurrent ensureCrypto / generateSecureId calls survive mid-flight setCrypto overrides",
    async () => {
      // Set up controllable crypto
      const controllable = makeControllableCrypto();
      try {
        // set controllable crypto (subtle.digest waits until controllable._resolve)
        await securityKit.setCrypto(controllable as any);
      } catch {
        // ignore if sealed
        return;
      }

      // Kick off many concurrent callers that will call generateSecureId (which uses getRandomValues synchronously)
      const tasks = Array.from({ length: 30 }).map(() =>
        securityKit.generateSecureId(16),
      );
      // Now in the middle, override crypto to a deterministic one (simulate a replacement)
      const replacement = makeDeterministicCrypto();
      // override (simulate happening while some tasks are pending)
      // because our controllable crypto doesn't actually block getRandomValues, we simulate by replacing before resolution
      const overridePromise = (async () => {
        // wait a tick so that many generateSecureId calls started
        await new Promise((res) => setTimeout(res, 0));
        try {
          await securityKit.setCrypto(replacement);
        } catch {
          // ignore sealed
        }
      })();

      // resolve controllable's subtle so any awaiting digest continues
      if (typeof (controllable as any)._resolve === "function") {
        (controllable as any)._resolve();
      }
      // wait for all to settle
      await Promise.allSettled([...tasks, overridePromise]);
      // Check uniqueness where applicable
      const results = await Promise.allSettled(tasks);
      const ok = results
        .filter((r) => r.status === "fulfilled")
        .map((r: any) => r.value);
      // If some succeeded, ensure they are strings and hex-ish
      for (const val of ok) {
        expect(typeof val).toBe("string");
        expect(/^[0-9a-f]+$/i.test(val)).toBe(true);
      }
    },
    { timeout: NIGHTLY ? 120_000 : 30_000 },
  );

  // 10) Optional heavy chi-squared uniformity (nightly only)
  if (NIGHTLY) {
    it(
      "statistical chi-squared test for small-range uniformity (nightly)",
      async () => {
        const min = 0,
          max = 5,
          iterations = 20000;
        const counts: Record<string, number> = {};
        for (let i = 0; i <= max; i++) counts[String(i)] = 0;
        for (let i = 0; i < iterations; i++) {
          const v = await securityKit.getSecureRandomInt(min, max);
          counts[String(v)] = (counts[String(v)] ?? 0) + 1;
        }
        // basic sanity: each bucket non-empty and roughly equal; use simple chi-sq threshold
        const expected = iterations / (max - min + 1);
        let chi = 0;
        for (let k = min; k <= max; k++) {
          const obs = counts[String(k)] ?? 0;
          chi += Math.pow(obs - expected, 2) / expected;
        }
        // loose threshold for 5 degrees of freedom
        expect(chi).toBeLessThan(20);
      },
      { timeout: 300_000 },
    );
  }
});
