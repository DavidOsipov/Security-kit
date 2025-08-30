// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * A library of general-purpose security utilities, hardened and built according
 * to a strict security constitution. It provides primitives for timing-safe
 * comparison, best-effort secure memory wiping, and safe logging.
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

import {
  InvalidParameterError,
  CryptoUnavailableError,
  IllegalStateError,
  sanitizeErrorForLogs,
} from "./errors";
import { ensureCrypto } from "./state";
import { environment, isDevelopment } from "./environment";
import { SHARED_ENCODER } from "./encoding";
import { setDevLogger } from "./dev-logger";

// Type definitions for cross-platform compatibility
interface GlobalWithBuffer {
  readonly Buffer?: {
    readonly isBuffer: (obj: unknown) => obj is Buffer;
  };
}

interface GlobalWithTypedArrays {
  readonly BigInt64Array?: new (length: number) => BigInt64Array;
  readonly BigUint64Array?: new (length: number) => BigUint64Array;
}

interface BufferLike {
  readonly constructor?: { readonly name: string };
}

interface TypedArrayWithFill {
  readonly fill?: (value: number) => unknown;
}

interface GlobalWithSharedArrayBuffer {
  readonly SharedArrayBuffer?: new (length: number) => SharedArrayBuffer;
}

// --- Telemetry ---

/**
 * Defines the shape of a function that can be registered to receive telemetry events.
 */
export type TelemetryHook = (
  name: string,
  value?: number,
  tags?: Record<string, string>,
) => void;

/**
 * A zero-argument callback function that unregisters a previously registered hook.
 */
type UnregisterCallback = () => void;

const telemetryState: { readonly hook: TelemetryHook | undefined } = {
  hook: undefined,
};

/**
 * Sanitizes telemetry tags against an allowlist to prevent accidental leakage of sensitive data.
 * @private
 */
function sanitizeMetricTags(
  tags?: Readonly<Record<string, string>>,
): Record<string, string> | undefined {
  if (!tags) return undefined;
  const out: Record<string, string> = {};
  const allow = new Set(["reason", "strict", "requireCrypto", "subtlePresent"]);
  for (const [key, value] of Object.entries(tags)) {
    if (allow.has(key)) {
      // eslint-disable-next-line functional/immutable-data
      out[key] = String(value).slice(0, 64);
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Registers a telemetry hook for the library. This MUST be called only once.
 * @param hook The telemetry function to call when metrics are emitted.
 * @returns A callback function to unregister the hook.
 * @throws {IllegalStateError} If the telemetry hook has already been registered.
 * @throws {InvalidParameterError} If the provided hook is not a function.
 */
export function registerTelemetry(hook: TelemetryHook): UnregisterCallback {
  if (telemetryState.hook) {
    throw new IllegalStateError("Telemetry hook has already been registered.");
  }
  if (typeof hook !== "function") {
    throw new InvalidParameterError("Telemetry hook must be a function.");
  }
  // eslint-disable-next-line functional/immutable-data
  (telemetryState as { hook: TelemetryHook | undefined }).hook = hook;

  return () => {
    // eslint-disable-next-line functional/immutable-data
    if (telemetryState.hook === hook) (telemetryState as { hook: TelemetryHook | undefined }).hook = undefined;
  };
}

/**
 * Safely invokes the registered telemetry hook with sanitized tags, catching any
 * errors to prevent them from affecting the library's execution.
 * @private
 */
function safeEmitMetric(
  name: string,
  value?: number,
  tags?: Record<string, string>,
): void {
  const { hook } = telemetryState;
  if (!hook) return;
  try {
    hook(name, value, sanitizeMetricTags(tags));
  } catch (error) {
    secureDevLog(
      "error",
      "telemetry-wrapper",
      "User-provided telemetry hook threw an error.",
      { error },
    );
  }
}

/**
 * Checks if the environment is configured for strict security mode.
 * @private
 */
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

/**
 * Validates that a value is an integer within a specified range.
 * @param value The numeric value to validate.
 * @param parameterName The name of the parameter being validated.
 * @param min The minimum allowed integer value.
 * @param max The maximum allowed integer value.
 * @throws {InvalidParameterError} If validation fails.
 */
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

/**
 * Validates that a value is a number between 0 and 1, inclusive.
 * @param probability The value to validate.
 * @throws {InvalidParameterError} If validation fails.
 */
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
 * ⚠️  IMPORTANT SECURITY NOTE: This is BEST-EFFORT ONLY. JavaScript's memory
 * model and garbage collector provide no guarantees that all copies of the
 * data will be removed from memory. For strong secrecy, use non-extractable
 * CryptoKey objects or the `createSecureZeroingBuffer` helper.
 *
 * @param typedArray - The typed array view to zero out.
 * @param options - Configuration options.
 * @param options.forbidShared - If true (default), throws an error if the view is backed by a SharedArrayBuffer.
 * @returns true if wipe attempts completed without thrown errors, false otherwise.
 */
export function secureWipe(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean },
): boolean {
  if (!typedArray) return true;
  if (typedArray.byteLength === 0) return true;
  const forbidShared = options?.forbidShared !== false;

  // Cross-realm SAB detection
  let isShared = false;
  try {
    const buf = typedArray.buffer as BufferLike;
    const tag = Object.prototype.toString.call(buf);
    const globalWithSAB = globalThis as GlobalWithSharedArrayBuffer;
    isShared =
      typeof globalWithSAB.SharedArrayBuffer !== "undefined" &&
      (tag === "[object SharedArrayBuffer]" ||
        buf.constructor?.name === "SharedArrayBuffer");
  } catch {
    // ignore detection errors
  }

  if (forbidShared && isShared) {
    if (isDevelopment()) {
      secureDevLog(
        "error",
        "secureWipe",
        "SharedArrayBuffer is not allowed for wiping",
        {
          isShared: true,
        },
      );
    }
    safeEmitMetric("secureWipe.blocked", 1, { reason: "shared" });
    return false;
  }

  if (isDevelopment() && typedArray.byteLength > 1024) {
    secureDevLog(
      "warn",
      "secureWipe",
      "Wiping a large buffer (>1KB). Prefer non-extractable CryptoKey objects.",
      { size: typedArray.byteLength },
    );
  }

  try {
    // Try strategies in order of preference
    return (
      tryNodeBufferWipe(typedArray) ||
      tryDataViewWipe(typedArray) ||
      tryBigIntWipe(typedArray) ||
      tryGenericFillWipe(typedArray) ||
      tryByteWiseWipe(typedArray)
    );
  } catch (err) {
    if (isDevelopment()) {
      secureDevLog("error", "secureWipe", "Wipe failed", {
        error: sanitizeErrorForLogs(err),
      });
    }
    safeEmitMetric("secureWipe.error", 1, { reason: "exception" });
    return false;
  }
}

/**
 * Attempts to wipe using Node.js Buffer.fill(0).
 */
function tryNodeBufferWipe(typedArray: ArrayBufferView): boolean {
  const maybeBuffer = typedArray as unknown as TypedArrayWithFill;
  const globalWithBuffer = globalThis as GlobalWithBuffer;
  const isNodeBuffer =
    typeof globalWithBuffer.Buffer !== "undefined" &&
    typeof globalWithBuffer.Buffer.isBuffer === "function" &&
    globalWithBuffer.Buffer.isBuffer(typedArray);

  if (isNodeBuffer && typeof maybeBuffer.fill === "function") {
    maybeBuffer.fill(0);
    safeEmitMetric("secureWipe.ok", 1, { strategy: "node-buffer" });
    return true;
  }
  return false;
}

/**
 * Attempts to wipe using DataView chunked zeroing.
 */
function tryDataViewWipe(typedArray: ArrayBufferView): boolean {
  try {
    const view = new DataView(
      typedArray.buffer,
      typedArray.byteOffset,
      typedArray.byteLength,
    );
    /* eslint-disable-next-line functional/no-let -- Mutable index required for performant chunked zeroing loop. */
    let i = 0;
    const n = view.byteLength;
    const STEP32 = 4;
    for (; i + STEP32 <= n; i += STEP32) view.setUint32(i, 0, true);
    for (; i < n; i++) view.setUint8(i, 0);
    safeEmitMetric("secureWipe.ok", 1, { strategy: "dataview" });
    return true;
  } catch (_error) {
    // DataView creation or access failed, try next strategy
    // eslint-disable-next-line sonarjs/no-ignored-exceptions -- Intentionally ignore DataView errors to try alternative wipe strategies
    return false;
  }
}

/**
 * Attempts to wipe BigInt typed arrays.
 */
function tryBigIntWipe(typedArray: ArrayBufferView): boolean {
  const globalWithTypedArrays = globalThis as GlobalWithTypedArrays;
  if (
    (globalWithTypedArrays.BigInt64Array &&
      typedArray instanceof globalWithTypedArrays.BigInt64Array) ||
    (globalWithTypedArrays.BigUint64Array &&
      typedArray instanceof globalWithTypedArrays.BigUint64Array)
  ) {
    const ta = typedArray as unknown as {
      readonly length: number;
      readonly [i: number]: bigint;
    };
    /* eslint-disable-next-line functional/no-let -- Mutable index required for performant BigInt array zeroing loop. */
    for (let i = 0; i < ta.length; i++) {
      // eslint-disable-next-line functional/immutable-data
      (ta as unknown as { [i: number]: bigint })[i] = 0n;
    }
    safeEmitMetric("secureWipe.ok", 1, { strategy: "bigint" });
    return true;
  }
  return false;
}

/**
 * Attempts to wipe using generic typed-array .fill(0).
 */
function tryGenericFillWipe(typedArray: ArrayBufferView): boolean {
  const generic = typedArray as unknown as TypedArrayWithFill;
  if (typeof generic.fill === "function") {
    generic.fill(0);
    safeEmitMetric("secureWipe.ok", 1, { strategy: "generic-fill" });
    return true;
  }
  return false;
}

/**
 * Attempts to wipe using last-resort byte-wise zeroing.
 */
function tryByteWiseWipe(typedArray: ArrayBufferView): boolean {
  const u8 = new Uint8Array(
    typedArray.buffer,
    typedArray.byteOffset,
    typedArray.byteLength,
  );
  /* eslint-disable-next-line functional/no-let -- Mutable index required for performant byte-wise zeroing loop. */
  for (let i = 0; i < u8.length; i++) u8[i] = 0;
  safeEmitMetric("secureWipe.ok", 1, { strategy: "u8-loop" });
  return true;
}

/**
 * @deprecated Use `createSecureZeroingBuffer` for a safer, lifecycle-aware API that helps prevent use-after-free errors.
 * @param length Length of the array to create.
 * @returns A new Uint8Array.
 */
export function createSecureZeroingArray(length: number): Uint8Array {
  validateNumericParam(length, "length", 1, 4096);
  return new Uint8Array(length);
}

/**
 * Creates a secure buffer for short-lived secret material, bundled with a
 * function to securely wipe it. This pattern enforces a secure lifecycle,
 * making it the recommended way to handle sensitive data in memory.
 *
 * @example
 * const secret = createSecureZeroingBuffer(32);
 * try {
 *   const keyMaterial = secret.get();
 *   // ... use keyMaterial
 * } finally {
 *   secret.free();
 * }
 *
 * @param length Length of the buffer to create.
 * @returns An object with methods to safely access and free the buffer.
 */
export function createSecureZeroingBuffer(length: number): {
  readonly get: () => Uint8Array;
  readonly free: () => boolean;
  readonly isFreed: () => boolean;
} {
  validateNumericParam(length, "length", 1, 4096);
  const view = new Uint8Array(length);
  /* eslint-disable-next-line functional/no-let -- Required for the stateful closure pattern. */
  let freed = false;
  return {
    get() {
      if (freed) {
        throw new IllegalStateError("Secure buffer has already been freed.");
      }
      return view;
    },
    free() {
      if (freed) return true; // Idempotent free
      const ok = secureWipe(view);
      freed = true;
      return ok;
    },
    isFreed() {
      return freed;
    },
  };
}

// --- Timing-Safe Comparison ---

/** Default maximum character length for timing-safe comparisons to prevent DoS attacks. */
export const MAX_COMPARISON_LENGTH = 4096;
/** Default maximum raw character length before Unicode normalization. */
export const MAX_RAW_INPUT_LENGTH = MAX_COMPARISON_LENGTH;

/**
 * Validates and normalizes input strings for secure comparison.
 * @private
 */
function validateAndNormalizeInputs(
  a: string | undefined,
  b: string | undefined,
): { readonly sa: string; readonly sb: string } {
  if (a === undefined || b === undefined) {
    throw new InvalidParameterError("Both inputs must be defined strings.");
  }

  const aStr = String(a);
  const bStr = String(b);

  if (
    aStr.length > MAX_RAW_INPUT_LENGTH ||
    bStr.length > MAX_RAW_INPUT_LENGTH
  ) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_RAW_INPUT_LENGTH} characters.`,
    );
  }

  const sa: string = aStr.normalize("NFC");
  const sb: string = bStr.normalize("NFC");

  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }

  return { sa, sb };
}

/**
 * Performs a constant-time string comparison to prevent timing attacks.
 * The function will always take the same amount of time for inputs up to
 * `MAX_COMPARISON_LENGTH`, regardless of where the first difference occurs.
 *
 * @param a The first string to compare.
 * @param b The second string to compare.
 * @returns True if the strings are equal.
 * @throws {InvalidParameterError} If inputs are too long or have invalid encoding.
 */
export function secureCompare(
  a: string | undefined,
  b: string | undefined,
): boolean {
  const { sa, sb } = validateAndNormalizeInputs(a, b);

  // Emit telemetry for near-limit inputs to detect DoS probing
  if (Math.max(sa.length, sb.length) >= MAX_COMPARISON_LENGTH - 64) {
    safeEmitMetric("secureCompare.nearLimit", 1, { reason: "near-limit" });
  }

  /* eslint-disable-next-line functional/no-let -- A mutable accumulator is required for a performant, constant-time comparison loop. */
  let diff = 0;
  /* eslint-disable-next-line functional/no-let -- A mutable index is standard and performant for a fixed-iteration for-loop. */
  for (let index = 0; index < MAX_COMPARISON_LENGTH; index++) {
    const ca = sa.charCodeAt(index) || 0;
    const cb = sb.charCodeAt(index) || 0;
    diff |= ca ^ cb;
  }

  return diff === 0 && sa.length === sb.length;
}

/**
 * Checks crypto availability and returns required objects.
 */
async function checkCryptoAvailability(options?: {
  readonly requireCrypto?: boolean;
}): Promise<{
  readonly strict: boolean;
  readonly crypto: Crypto;
  readonly subtle: SubtleCrypto;
}> {
  const strict = options?.requireCrypto === true || isSecurityStrict();

  const crypto = await ensureCrypto();
  const subtle = (crypto as { readonly subtle?: SubtleCrypto }).subtle;
  if (!subtle?.digest) {
    if (strict) {
      throw new CryptoUnavailableError("SubtleCrypto.digest is unavailable.");
    }
    safeEmitMetric("secureCompare.fallback", 1, {
      requireCrypto: String(!!options?.requireCrypto),
      subtlePresent: "0",
      strict: strict ? "1" : "0",
    });
    throw new CryptoUnavailableError("SubtleCrypto.digest is unavailable.");
  }

  return { strict, crypto, subtle };
}

/**
 * Performs constant-time comparison of two Uint8Arrays.
 */
function compareUint8Arrays(ua: Uint8Array, ub: Uint8Array): boolean {
  // Constant-time compare on fixed digest size
  /* eslint-disable-next-line functional/no-let -- A mutable accumulator is required for a performant, constant-time comparison loop. */
  let diff = 0;
  const len = Math.max(ua.length, ub.length, 32);
  for (let i = 0; i < len; i++) {
    const ca = ua[i] ?? 0;
    const cb = ub[i] ?? 0;
    diff |= ca ^ cb;
  }
  return diff === 0 && ua.length === ub.length;
}

/**
 * Asynchronously performs a timing-safe string comparison, leveraging the
 * Web Crypto API for the highest security guarantees.
 *
 * @param a The first string to compare.
 * @param b The second string to compare.
 * @param options Configuration for the comparison.
 * @param options.requireCrypto If true, the function will throw an error if the
 *   Web Crypto API is unavailable, enforcing the "Fail Loudly, Fail Safely"
 *   principle. **This is the recommended setting for all security-critical
 *   comparisons**, per the Security Constitution.
 * @returns A promise that resolves to true if the strings are equal.
 */
export async function secureCompareAsync(
  a: string | undefined,
  b: string | undefined,
  options?: { readonly requireCrypto?: boolean },
): Promise<boolean> {
  const { sa, sb } = validateAndNormalizeInputs(a, b);

  // Emit telemetry for near-limit inputs to detect DoS probing
  if (Math.max(sa.length, sb.length) >= MAX_COMPARISON_LENGTH - 64) {
    safeEmitMetric("secureCompareAsync.nearLimit", 1, { reason: "near-limit" });
  }

  try {
    const { subtle } = await checkCryptoAvailability(options);

    /* eslint-disable-next-line functional/no-let -- Mutable variables are needed to hold buffer references that must be wiped in a finally block. */
    let ua: Uint8Array | undefined;
    /* eslint-disable-next-line functional/no-let -- Mutable variables are needed to hold buffer references that must be wiped in a finally block. */
    let ub: Uint8Array | undefined;

    try {
      const [da, db] = await Promise.all([
        subtle.digest("SHA-256", SHARED_ENCODER.encode(sa)),
        subtle.digest("SHA-256", SHARED_ENCODER.encode(sb)),
      ]);
      ua = new Uint8Array(da);
      ub = new Uint8Array(db);

      return compareUint8Arrays(ua, ub);
    } finally {
      // Best-effort wipe
      if (ua) secureWipe(ua);
      if (ub) secureWipe(ub);
    }
  } catch (error) {
    // Handle crypto unavailability by falling back to non-crypto comparison
    if (error instanceof CryptoUnavailableError) {
      return secureCompare(sa, sb);
    }

    // Re-throw other crypto errors in strict mode
    const strict = options?.requireCrypto === true || isSecurityStrict();
    if (strict) {
      if (!(error instanceof CryptoUnavailableError)) {
        // normalize to crypto unavailable if it was another crypto failure
        throw new CryptoUnavailableError(
          "Cryptographic compare failed in strict mode.",
        );
      }
      throw error;
    }

    if (isDevelopment()) {
      secureDevLog(
        "error",
        "secureCompareAsync",
        "Crypto compare failed; falling back",
        {
          error: sanitizeErrorForLogs(error),
        },
      );
    }
    safeEmitMetric("secureCompare.fallback", 1, {
      requireCrypto: String(!!options?.requireCrypto),
      subtlePresent: "unknown",
      strict: strict ? "1" : "0",
    });
    return secureCompare(sa, sb);
  }
}

// --- Safe Logging & Redaction ---

/** Maximum recursion depth for the redaction function. */
export const MAX_REDACT_DEPTH = 8;
/** Maximum length of a string in logs before it is truncated. */
export const MAX_LOG_STRING = 8192;

const JWT_LIKE_REGEX = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}$/;
const REDACTED_VALUE = "[REDACTED]";
const SAFE_KEY_REGEX = /^[\w.-]{1,64}$/;

/**
 * Checks if a key contains sensitive API-related terms.
 */
function isApiKey(key: string): boolean {
  return /\b(?:api[_-]?key|x[_-]?api[_-]?key)\b/i.test(key);
}

/**
 * Checks if a key contains sensitive token-related terms.
 */
function isTokenKey(key: string): boolean {
  return /\b(?:access[_-]?token|refresh[_-]?token|bearer|token)\b/i.test(key);
}

/**
 * Checks if a key contains sensitive authentication terms.
 */
function isAuthKey(key: string): boolean {
  return /\b(?:password|passphrase|secret|credential|private[_-]?key|authorization)\b/i.test(
    key,
  );
}

/**
 * Checks if a key contains other sensitive terms.
 */
function isOtherSensitiveKey(key: string): boolean {
  return /\b(?:jwt|session|cert|signature)\b/i.test(key);
}

/**
 * Checks if a key should be redacted based on security patterns.
 */
function isSensitiveKey(key: string): boolean {
  return (
    isApiKey(key) ||
    isTokenKey(key) ||
    isAuthKey(key) ||
    isOtherSensitiveKey(key)
  );
}

function _truncateIfLong(s: string): string {
  return s.length > MAX_LOG_STRING
    ? s.slice(0, MAX_LOG_STRING) +
        `...[TRUNCATED ${s.length - MAX_LOG_STRING} chars]`
    : s;
}

function _redactPrimitive(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (JWT_LIKE_REGEX.test(value)) return REDACTED_VALUE;
  if (
    /(?:^|[\s,&])(?:password|pass|token|secret|bearer|jwt|authorization)\s*[=:]/i.test(
      value,
    )
  ) {
    return REDACTED_VALUE;
  }
  if (value.length > MAX_LOG_STRING) return _truncateIfLong(value);
  return value;
}

function _redactObject(
  object: Record<string, unknown>,
  depth: number,
): unknown {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Object.create(null) returns any, but we need dynamic property assignment for logging
  const out = Object.create(null) as Record<string, unknown>;
  for (const [key, rawValue] of Object.entries(object)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      continue; // avoid prototype pollution in logs
    }
    if (isSensitiveKey(key)) {
      // eslint-disable-next-line functional/immutable-data
      out[key] = REDACTED_VALUE;
      continue;
    }
    if (!SAFE_KEY_REGEX.test(key)) {
      // keep but mark unsafe key
      // eslint-disable-next-line functional/immutable-data
      out[`__unsafe_key__`] = true;
    }
    if (typeof rawValue === "string") {
      // eslint-disable-next-line functional/immutable-data
      out[key] = _redactPrimitive(rawValue);
    } else if (rawValue && typeof rawValue === "object") {
      // eslint-disable-next-line functional/immutable-data
      out[key] = _redact(rawValue, depth + 1);
    } else {
      // eslint-disable-next-line functional/immutable-data
      out[key] = rawValue;
    }
  }
  return out;
}

function _cloneAndNormalizeForLogging(
  data: unknown,
  depth: number,
  /* eslint-disable-next-line functional/prefer-readonly-type -- Mutable Set required for cycle detection algorithm */
  visited: Set<unknown>,
): unknown {
  if (depth >= MAX_REDACT_DEPTH) {
    return { __redacted: true, reason: "max-depth" };
  }
  if (data === null || typeof data !== "object") {
    if (typeof data === "bigint") return `${data.toString()}n`;
    return data;
  }
  if (visited.has(data)) {
    return { __redacted: true, reason: "circular-reference" };
  }

  visited.add(data);
  try {
    return handleSpecialObjectTypes(data, depth, visited);
  } finally {
    visited.delete(data);
  }
}

/**
 * Handles special object types for logging normalization.
 */
function handleSpecialObjectTypes(
  data: object,
  depth: number,
  /* eslint-disable-next-line functional/prefer-readonly-type -- Mutable Set required for cycle detection algorithm */
  visited: Set<unknown>,
): unknown {
  if (data instanceof Error) {
    return sanitizeErrorForLogs(data);
  }
  if (data instanceof Date) {
    return data.toISOString();
  }
  if (data instanceof ArrayBuffer) {
    return { __arrayBuffer: data.byteLength };
  }
  if (ArrayBuffer.isView(data)) {
    return handleTypedArray(data);
  }
  if (Array.isArray(data)) {
    return handleArray(data, depth, visited);
  }
  return handlePlainObject(data, depth, visited);
}

/**
 * Handles TypedArray objects for logging.
 */
function handleTypedArray(data: ArrayBufferView): unknown {
  return {
    __typedArray: {
      ctor: (data as { readonly constructor?: { readonly name: string } })
        ?.constructor?.name,
      byteLength: data.byteLength,
    },
  };
}

/**
 * Handles Array objects for logging.
 */
function handleArray(
  data: readonly unknown[],
  depth: number,
  /* eslint-disable-next-line functional/prefer-readonly-type -- Mutable Set required for cycle detection algorithm */
  visited: Set<unknown>,
): unknown {
  const result = [];
  for (const item of data) {
    // eslint-disable-next-line functional/immutable-data
    result.push(_cloneAndNormalizeForLogging(item, depth + 1, visited));
  }
  return result;
}

/**
 * Handles plain objects for logging.
 */
function handlePlainObject(
  data: object,
  depth: number,
  /* eslint-disable-next-line functional/prefer-readonly-type -- Mutable Set required for cycle detection algorithm */
  visited: Set<unknown>,
): unknown {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Object.create(null) returns any, but we need dynamic property assignment for logging
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(data)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      continue; // avoid prototype pollution in logs
    }
    try {
      // eslint-disable-next-line functional/immutable-data
      result[key] = _cloneAndNormalizeForLogging(
        (data as Record<string, unknown>)[key],
        depth + 1,
        visited,
      );
    } catch {
      // eslint-disable-next-line sonarjs/no-ignored-exceptions -- Intentionally ignore getter errors during logging to prevent log failures
      // eslint-disable-next-line functional/immutable-data
      result[key] = { __redacted: true, reason: "getter-threw" };
    }
  }
  return result;
}

/**
 * Recursively sanitizes and redacts sensitive information from an object
 * before it is logged. This function is for internal use.
 * @internal
 */
export function _redact(data: unknown, depth = 0): unknown {
  if (depth === 0) {
    const sanitizedData = _cloneAndNormalizeForLogging(data, depth, new Set());
    return _redact(sanitizedData, 1);
  }

  if (data === null || typeof data !== "object") return _redactPrimitive(data);
  if (Array.isArray(data)) {
    return data.map((item) => _redact(item, depth + 1));
  }
  return _redactObject(data as Record<string, unknown>, depth);
}

type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * Internal console wrapper for development-only logging.
 * @internal
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

/**
 * Logs a message and a context object in development environments ONLY.
 * The context object is automatically redacted to prevent accidental leakage
 * of sensitive information.
 * @param level The log level.
 * @param component The name of the component or module logging the message.
 * @param message The log message.
 * @param context An optional object containing additional context.
 */
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
      const safeEvent = {
        level: logEntry.level,
        component: logEntry.component,
        message: logEntry.message,
      };
      document.dispatchEvent(
        new CustomEvent("security-kit:log", { detail: safeEvent }),
      );
    } catch {
      /* ignore */
    }
  }

  const message_ = `[${logEntry.level}] (${component}) ${message}`;
  _devConsole(level, message_, safeContext);
}

// Set the logger for the dev-logger facade
setDevLogger(secureDevLog);

// --- Internal Utilities ---
