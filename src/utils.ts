// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * General-purpose security utilities, including timing-safe comparison,
 * secure wiping, and safe logging.
 * @module
 */

/*
 * NOTE: This file performs a small number of intentional, well-audited
 * mutations and uses short, commonly-understood abbreviations for internal
 * helper names (e.g. "dev" for development-only helpers). Renaming these
 * identifiers risks larger refactors across the codebase and obscures the
 * intent in security-critical helpers. We therefore selectively disable the
 * `unicorn/prevent-abbreviations` rule for this file. Other rules are
 * handled with narrowly-scoped disables where mutation is required.
 */
/* eslint-disable unicorn/prevent-abbreviations */

import { InvalidParameterError, CryptoUnavailableError } from "./errors";
import { ensureCrypto } from "./state";
import { environment, isDevelopment } from "./environment";
import { SHARED_ENCODER } from "./encoding";

// Telemetry hook: optional runtime registration for metrics. Default is undefined.
export type TelemetryHook = (
  name: string,
  value?: number,
  tags?: Record<string, string>,
) => void;
export let emitMetric: TelemetryHook | undefined = undefined;
export function registerTelemetry(hook: TelemetryHook): void {
  emitMetric = hook;
}

function isSecurityStrict(): boolean {
  try {
    if (typeof process === "undefined") return false;
    const env = process.env as Record<string, string> | undefined;
    return env?.["SECURITY_STRICT"] === "1";
  } catch {
    return false;
  }
}

// --- Parameter Validation ---
export function validateNumericParam(
  value: number,
  parameterName: string,
  min: number,
  max: number,
): void {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  ) {
    throw new InvalidParameterError(
      `${parameterName} must be an integer between ${min} and ${max}.`,
    );
  }
}

export function validateProbability(probability: number): void {
  if (
    typeof probability !== "number" ||
    !(probability >= 0 && probability <= 1)
  ) {
    throw new InvalidParameterError(
      `Probability must be a number between 0 and 1.`,
    );
  }
}

// --- Secure Wiping ---
/**
 * Attempts to zero out the provided typed array view.
 *
 * ⚠️  IMPORTANT SECURITY NOTE: This is BEST-EFFORT ONLY
 *
 * JavaScript engines may create hidden copies during:
 * - Garbage collection
 * - JIT optimizations
 * - Memory management operations
 * - String operations
 *
 * This function CANNOT guarantee removal of all copies from memory.
 *
 * For strong secrecy guarantees, prefer non-extractable CryptoKey objects
 * created with `createOneTimeCryptoKey` which cannot be extracted to memory.
 *
 * @param typedArray - The typed array view to zero out
 * @returns true if wipe attempts completed without thrown errors (best-effort),
 *          false if an error occurred during wipe attempts.
 */
export function secureWipe(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean },
): boolean {
  if (!typedArray) return true;
  const forbidShared = options?.forbidShared !== false; // default true

  // Safer cross-realm detection of SharedArrayBuffer backing:
  try {
    if (forbidShared && typeof SharedArrayBuffer !== "undefined") {
      const buf = (typedArray as ArrayBufferView).buffer;
      // Cross-realm-safe constructor name check
      const ctorName =
        Object.prototype.hasOwnProperty.call(buf, "constructor") &&
        (buf as any).constructor &&
        (buf as any).constructor.name;
      if (ctorName === "SharedArrayBuffer") {
        throw new InvalidParameterError(
          "secureWipe: SharedArrayBuffer-backed views cannot be securely wiped.",
        );
      }
    }
  } catch {
    // ignore feature detection failures
  }

  if (isDevelopment() && typedArray.byteLength > 1024) {
    secureDevLog(
      "warn",
      "secureWipe",
      "Wiping a large buffer (>1KB). Prefer non-extractable CryptoKey objects for secrets.",
    );
  }
  try {
    // Delegate specific wiping strategies to helpers to keep this function
    // small and auditable for static analysis.
    const tryNodeBufferWipe = (): boolean => {
      // Narrow cast and check for Node Buffer semantics (safe global access)
      type BufferNS = { readonly isBuffer?: (x: unknown) => boolean };
      const bufNS: BufferNS | undefined = (
        globalThis as unknown as { readonly Buffer?: BufferNS }
      ).Buffer;
      const isNodeBuffer = !!bufNS?.isBuffer && bufNS.isBuffer(typedArray);
      if (!isNodeBuffer) return false;
      (typedArray as unknown as Buffer).fill(0);
      return true;
    };

    const tryDataViewWipe = (): boolean => {
      if (typeof DataView === "undefined" || !(typedArray instanceof DataView))
        return false;
      new Uint8Array(
        typedArray.buffer,
        typedArray.byteOffset,
        typedArray.byteLength,
      ).fill(0);
      return true;
    };

    const tryBigIntWipe = (): boolean => {
      if (
        typeof BigUint64Array !== "undefined" &&
        typedArray instanceof BigUint64Array
      ) {
        const ta = typedArray;
        ta.fill(0n);
        return true;
      }
      if (
        typeof BigInt64Array !== "undefined" &&
        typedArray instanceof BigInt64Array
      ) {
        const ta = typedArray;
        ta.fill(0n);
        return true;
      }
      return false;
    };

    const tryGenericWipe = (): boolean => {
      // Only perform a generic wipe when the underlying buffer looks usable.
      if (!typedArray?.buffer) return false;
      if (typeof (typedArray as Uint8Array).fill === "function") {
        const ta = typedArray as Uint8Array;
        ta.fill(0);
        return true;
      }
      const view = new Uint8Array(
        typedArray.buffer,
        typedArray.byteOffset,
        typedArray.byteLength,
      );
      view.fill(0);
      return true;
    };

    // Compute the first successful strategy once and reuse it for logging.
    let strategy: string | undefined;
    const ok = (() => {
      if (tryNodeBufferWipe()) {
        strategy = "node-buffer";
        return true;
      }
      if (tryDataViewWipe()) {
        strategy = "dataview";
        return true;
      }
      if (tryBigIntWipe()) {
        strategy = "bigint";
        return true;
      }
      if (tryGenericWipe()) {
        strategy = "generic";
        return true;
      }
      strategy = "none";
      return false;
    })();

    // Dev-only: record which strategy succeeded to help audits/debugging
    if (isDevelopment()) {
      secureDevLog("debug", "secureWipe", `wiping strategy=${strategy}`, {
        byteLength: typedArray.byteLength,
        forbidShared,
        strategy,
      });
    }

    return ok;
  } catch (err) {
    // best-effort: surface errors in development to make issues visible
    if (isDevelopment()) {
      secureDevLog("error", "secureWipe", "failed to wipe buffer", {
        error: err,
      });
    }
    return false;
  }
}

/**
 * Creates a Uint8Array intended for short-lived secret material.
 * This helper makes it explicit that the returned array should be
 * passed to secureWipe() when no longer needed, and that callers
 * should avoid reusing their own buffers in sensitive APIs.
 *
 * @param length - Length of the array to create
 * @returns A new Uint8Array suitable for secure wiping
 */
export function createSecureZeroingArray(length: number): Uint8Array {
  validateNumericParam(length, "length", 1, 4096);
  return new Uint8Array(length);
}

// --- Timing-Safe Comparison ---
const MAX_COMPARISON_LENGTH = 4096;
const MAX_RAW_INPUT_LENGTH = MAX_COMPARISON_LENGTH; // pre-normalization guard

export function secureCompare(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const aStr = String(a ?? "");
  const bStr = String(b ?? "");
  // Pre-check raw lengths to avoid expensive normalization on attacker-supplied huge inputs
  if (
    aStr.length > MAX_RAW_INPUT_LENGTH ||
    bStr.length > MAX_RAW_INPUT_LENGTH
  ) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_RAW_INPUT_LENGTH} characters.`,
    );
  }
  const sa = aStr.normalize("NFC");
  const sb = bStr.normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }
  // Perform a fixed-time loop up to MAX_COMPARISON_LENGTH to avoid leaking
  // the actual input lengths via timing. Reading beyond the string length
  // yields NaN from charCodeAt which we coerce to 0.
  /* eslint-disable-next-line functional/no-let -- fixed-time loop requires a mutable accumulator */
  let diff = 0;
  /* eslint-disable-next-line functional/no-let -- loop index is intentionally mutable for performance and constant-time semantics */
  for (let index = 0; index < MAX_COMPARISON_LENGTH; index++) {
    const ca = sa.charCodeAt(index) || 0;
    const cb = sb.charCodeAt(index) || 0;
    diff |= ca ^ cb;
  }
  // Also require exact length match; the timing above is constant regardless
  // of lengths, so returning length equality does not leak timing.
  return diff === 0 && sa.length === sb.length;
}

export async function secureCompareAsync(
  a: string | null | undefined,
  b: string | null | undefined,
  options?: { readonly requireCrypto?: boolean },
): Promise<boolean> {
  /**
   * Timing-safe comparison that uses the platform SubtleCrypto.digest when available.
   * Options:
   * - requireCrypto: when true, throw CryptoUnavailableError or any underlying error
   *   preventing the use of SubtleCrypto to enforce strict crypto usage.
   */
  const aStr = String(a ?? "");
  const bStr = String(b ?? "");
  // Pre-check raw lengths before normalization
  if (
    aStr.length > MAX_RAW_INPUT_LENGTH ||
    bStr.length > MAX_RAW_INPUT_LENGTH
  ) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_RAW_INPUT_LENGTH} characters.`,
    );
  }
  const sa = aStr.normalize("NFC");
  const sb = bStr.normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }

  try {
    const crypto = await ensureCrypto();
    const subtle = (crypto as { readonly subtle?: SubtleCrypto }).subtle;
    if (!subtle?.digest) {
      // Emit metric when falling back so operators can detect it.
      emitMetric?.("securitykit.secureCompareAsync.fallback", 1, {
        requireCrypto: String(!!options?.requireCrypto),
      });
      if (options?.requireCrypto || isSecurityStrict()) {
        throw new CryptoUnavailableError(
          "SubtleCrypto.digest is unavailable in this environment.",
        );
      }
      secureDevLog(
        "warn",
        "security-kit",
        "SubtleCrypto unavailable; falling back to sync compare",
      );
      return secureCompare(sa, sb);
    }
    const digestFor = (string_: string) =>
      subtle.digest("SHA-256", SHARED_ENCODER.encode(string_));
    /* eslint-disable-next-line functional/no-let -- buffers are assigned in try/finally and wiped */
    let va: Uint8Array | undefined, vb: Uint8Array | undefined;
    try {
      const [da, db] = await Promise.all([digestFor(sa), digestFor(sb)]);
      va = new Uint8Array(da);
      vb = new Uint8Array(db);
      if (va.length !== vb.length) return false;
      /* eslint-disable-next-line functional/no-let -- accumulator for bytewise comparison */
      let diff = 0;
      /* eslint-disable-next-line functional/no-let -- index used in a tight loop for performance */
      for (let index = 0; index < va.length; index++) {
        diff |= (va[index] ?? 0) ^ (vb[index] ?? 0);
      }
      return diff === 0;
    } finally {
      if (va) secureWipe(va);
      if (vb) secureWipe(vb);
    }
  } catch (error) {
    // If caller requested strict crypto, surface any failure to use crypto.
    if (options?.requireCrypto) throw error;
    secureDevLog(
      "error",
      "security-kit",
      "secureCompareAsync failed; falling back to sync compare",
      { error },
    );
    return secureCompare(sa, sb);
  }
}

// --- Safe Logging & Redaction ---
const MAX_REDACT_DEPTH = 8;
const SECRET_KEY_REGEX =
  /token|secret|password|pass|auth|key|bearer|session|credential|jwt|signature|cookie|private|cert/i;
const JWT_LIKE_REGEX = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}$/;
const REDACTED_VALUE = "[REDACTED]";
const SAFE_KEY_REGEX = /^[\w.-]{1,64}$/;
const MAX_LOG_STRING = 8192;

function _truncateIfLong(s: string): string {
  return s.length > MAX_LOG_STRING
    ? s.slice(0, MAX_LOG_STRING) +
        `...[TRUNCATED ${s.length - MAX_LOG_STRING} chars]`
    : s;
}

function _redactPrimitive(value: unknown): unknown {
  if (typeof value !== "string") return value;
  // value-based redaction for JWT-like tokens and common inline secrets
  if (JWT_LIKE_REGEX.test(value)) return REDACTED_VALUE;
  if (
    /password=|token=|secret=|bearer\s+|jwt=|authorization:\s*bearer/i.test(
      value,
    )
  )
    return REDACTED_VALUE;
  if (value.length > MAX_LOG_STRING) return _truncateIfLong(value);
  return value;
}

function _redactObject(
  object: Record<string, unknown>,
  depth: number,
): unknown {
  const out: Record<string, unknown> = Object.create(null);
  for (const [key, rawValue] of Object.entries(object)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor")
      continue;
    if (SECRET_KEY_REGEX.test(key)) {
      out[key] = REDACTED_VALUE;
      continue;
    }
    if (!SAFE_KEY_REGEX.test(key)) continue;
    if (typeof rawValue === "string") {
      out[key] = _redactPrimitive(rawValue);
    } else {
      out[key] = _redact(rawValue, depth + 1);
    }
  }
  return out;
}

export function _redact(data: unknown, depth = 0): unknown {
  if (depth >= MAX_REDACT_DEPTH)
    return { __redacted: true, reason: "max-depth" };
  if (data === null || typeof data !== "object") return _redactPrimitive(data);
  if (Array.isArray(data)) return data.map((item) => _redact(item, depth + 1));
  return _redactObject(data as Record<string, unknown>, depth);
}

type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Internal dev-only console wrapper.
 * All direct console.* calls for development logging should live here.
 * This makes it trivial for static checks to allow exactly this function.
 */
export function _devConsole(
  level: LogLevel,
  message: string,
  safeContext: unknown,
): void {
  if (environment.isProduction) return;
  switch (level) {
    case "debug":
      console.debug(message, safeContext);
      break;
    case "info":
      console.info(message, safeContext);
      break;
    case "warn":
      console.warn(message, safeContext);
      break;
    case "error":
      console.error(message, safeContext);
      break;
    default:
      console.info(message, safeContext);
  }
}

export function secureDevLog(
  level: LogLevel,
  component: string,
  message: string,
  context: unknown = {},
): void {
  if (environment.isProduction) return;
  const safeContext = _redact(context);
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    component,
    message,
    context: safeContext,
  };

  if (typeof document !== "undefined" && typeof CustomEvent !== "undefined") {
    try {
      document.dispatchEvent(
        new CustomEvent("security-kit:log", { detail: logEntry }),
      );
    } catch {
      /* ignore */
    }
  }

  const message_ = `[${logEntry.level}] (${component}) ${message}`;
  // Delegate actual console interaction to the internal wrapper. This
  // centralizes console usage in one function which the sanitizer can
  // explicitly allow by name.
  _devConsole(level, message_, safeContext);
}

/** @deprecated Use `secureDevLog` instead. */
export function secureDevNotify(
  type: LogLevel,
  component: string,
  data: unknown = {},
): void {
  if (isDevelopment()) {
    console.warn(
      "[security-kit] `secureDevNotify` is deprecated. Use `secureDevLog`.",
    );
  }
  secureDevLog(type, component, "Legacy notification", data);
}

// --- Internal Utilities ---
export function _arrayBufferToBase64(buf: ArrayBuffer): string {
  // Prefer Node Buffer when available
  if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
    // Ensure consistent behavior across Node versions by wrapping in Uint8Array
    return Buffer.from(new Uint8Array(buf)).toString("base64");
  }

  // Browser fallback: chunked binary-to-string + btoa
  const bytes = new Uint8Array(buf);
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    // create a small subarray to avoid apply limits
    const slice = bytes.subarray(i, i + CHUNK);
    // convert to string in a robust way
    binary += String.fromCharCode.apply(undefined, Array.from(slice));
  }

  if (typeof btoa === "function") return btoa(binary);

  // As a last resort, if no btoa is available, fail loudly to avoid producing
  // incorrect encodings silently.
  throw new Error("No base64 encoder available in this environment.");
}

// Test API global is managed via registerTestApi / unregisterTestApi.

/**
 * Test-only API registration: tests should call this in their setup to
 * enable the test-only helper. This avoids `require()` inside `src` and
 * preserves pure ESM compatibility for consumers.
 */
export function registerTestApi(assertTestApiAllowed: () => void): void {
  // runtime guard for test-only API usage
  assertTestApiAllowed();
  // Assign the internal function for test use (typed global)
  // Use any-cast to allow assignment to test-only global without changing global typing
  (globalThis as any).__test_arrayBufferToBase64 = _arrayBufferToBase64;
}

export function unregisterTestApi(): void {
  try {
    (globalThis as any).__test_arrayBufferToBase64 = undefined;
  } catch {
    // ignore
  }
}

export function getTestArrayBufferToBase64():
  | ((buf: ArrayBuffer) => string)
  | undefined {
  return (
    globalThis as unknown as {
      readonly __test_arrayBufferToBase64?:
        | ((buf: ArrayBuffer) => string)
        | undefined;
    }
  ).__test_arrayBufferToBase64;
}

// Test-only named export used by the public index for test harnesses. Keep
// this as a stable named export so consumers of the test API can import it
// directly when running in test environments that opt-in.
export const __test_arrayBufferToBase64 = _arrayBufferToBase64;

/**
 * Expose a getter for test harnesses to avoid relying on global mutation.
 * Tests can read (globalThis as any).__test_arrayBufferToBase64 or call registerTestApi.
 */
