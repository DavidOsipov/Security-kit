// SPDX-License-Identifier: LGPL-3.0-or-later
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
/*
 * The helpers in this file intentionally perform a very small number of
 * well-audited mutations (lifecycle flags, telemetry registration, and
 * efficient buffer wiping). We prefer narrow, inline disables next to the
 * actual mutation sites rather than blanket file-level disables. The file
 * keeps minimal and behavior-preserving edits only.
 */

import {
  InvalidParameterError,
  CryptoUnavailableError,
  IllegalStateError,
  sanitizeErrorForLogs,
} from "./errors";
import { ensureCrypto } from "./state";
import { environment, isDevelopment } from "./environment";
import { SHARED_ENCODER } from "./encoding";
import { setDevelopmentLogger_ } from "./dev-logger";
import { getLoggingConfig } from "./config";

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

// --- Module-level constants (performance, clarity, auditability) ---
const METRIC_TAG_ALLOW = new Set([
  "reason",
  "strict",
  "requireCrypto",
  "subtlePresent",
]);

/** Minimum number of bytes to always compare to avoid trivial short-circuits. */
const MIN_COMPARE_BYTES = 32;

/* eslint-disable-next-line functional/no-let -- telemetry hook must be mutable for register/unregister */
let telemetryHook: TelemetryHook | undefined;

/**
 * Sanitizes telemetry tags against an allowlist to prevent accidental leakage of sensitive data.
 * @private
 */
function sanitizeMetricTags(
  tags?: Readonly<Record<string, string>>,
): Record<string, string> | undefined {
  if (!tags) return undefined;
  const obj = Object.entries(tags).reduce(
    (acc, [k, v]) => {
      if (!METRIC_TAG_ALLOW.has(k)) return acc;
      return { ...acc, [k]: String(v).slice(0, 64) };
    },
    {} as Record<string, string>,
  );
  return Object.keys(obj).length > 0 ? obj : undefined;
}

/**
 * Registers a telemetry hook for the library. This MUST be called only once.
 * @param hook The telemetry function to call when metrics are emitted.
 * @returns A callback function to unregister the hook.
 * @throws {IllegalStateError} If the telemetry hook has already been registered.
 * @throws {InvalidParameterError} If the provided hook is not a function.
 */
export function registerTelemetry(hook: TelemetryHook): UnregisterCallback {
  if (telemetryHook) {
    throw new IllegalStateError("Telemetry hook has already been registered.");
  }
  if (typeof hook !== "function") {
    throw new InvalidParameterError("Telemetry hook must be a function.");
  }
  telemetryHook = hook;

  return () => {
    if (telemetryHook === hook) telemetryHook = undefined;
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
  const hook = telemetryHook;
  if (!hook) return;
  // Offload user hook to a microtask to avoid blocking hot paths.
  const payloadTags = sanitizeMetricTags(tags);
  const call = (): void => {
    try {
      hook(name, value, payloadTags);
    } catch {
      /* swallow user hook errors */
    }
  };
  if (typeof queueMicrotask === "function") {
    queueMicrotask(call);
  } else {
    void Promise.resolve().then(call);
  }
}

/**
 * Public wrapper for emitting telemetry metrics in a safe, non-blocking way.
 * This calls the internal safeEmitMetric and is the supported public API for
 * other modules to emit library telemetry.
 */
export function emitMetric(
  name: string,
  value?: number,
  tags?: Record<string, string>,
): void {
  try {
    safeEmitMetric(name, value, tags);
  } catch {
    /* swallow — telemetry must not throw */
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
  const isShared = isSharedArrayBufferView(typedArray);

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
 * Detect whether a given ArrayBufferView appears to be backed by a SharedArrayBuffer.
 *
 * This helper uses cross-realm safe detection by checking both the toStringTag
 * and constructor name, guarded behind a runtime feature probe for SharedArrayBuffer.
 * It intentionally swallows exotic prototype tricks and returns false on errors to avoid
 * throwing in hot paths. Prefer rejecting SharedArrayBuffer inputs at call sites.
 */
export function isSharedArrayBufferView(view: ArrayBufferView): boolean {
  try {
    const buf = view.buffer as BufferLike;
    const tag = Object.prototype.toString.call(buf);
    const globalWithSAB = globalThis as GlobalWithSharedArrayBuffer;
    if (typeof globalWithSAB.SharedArrayBuffer === "undefined") return false;
    // Prefer reliable tag or instanceof checks; avoid constructor name heuristics
    if (tag === "[object SharedArrayBuffer]") return true;
    try {
      // Cross-realm instanceof should still work for SAB in most engines
      return buf instanceof globalWithSAB.SharedArrayBuffer;
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

/**
 * Attempts to wipe using Node.js Buffer.fill(0).
 */
function tryNodeBufferWipe(typedArray: ArrayBufferView): boolean {
  function looksLikeNodeBuffer(
    obj: unknown,
  ): obj is { readonly fill?: (v: number) => unknown } {
    try {
      const g = globalThis as GlobalWithBuffer;
      return (
        typeof g.Buffer !== "undefined" &&
        typeof g.Buffer.isBuffer === "function" &&
        (g.Buffer.isBuffer as (o: unknown) => boolean)(obj)
      );
    } catch {
      return false;
    }
  }
  const maybeBuffer = typedArray as unknown as TypedArrayWithFill;
  const isNodeBuffer = looksLikeNodeBuffer(typedArray);

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

    // loop counter mutation is intentional for chunked DataView writes
    // eslint-disable-next-line functional/no-let -- loop counter required for chunked wipe
    let i = 0;
    const n = view.byteLength;
    const STEP32 = 4;
    for (; i + STEP32 <= n; i += STEP32) view.setUint32(i, 0, true);
    for (; i < n; i++) view.setUint8(i, 0);
    safeEmitMetric("secureWipe.ok", 1, { strategy: "dataview" });
    return true;
  } catch (_error) {
    // DataView creation or access failed, try next strategy
    // Log sanitized error in development to aid debugging but don't expose raw error contents
    if (isDevelopment()) {
      secureDevLog(
        "warn",
        "secureWipe",
        "DataView wipe failed, falling back to alternative wipe",
        {
          error: sanitizeErrorForLogs(_error),
        },
      );
    }

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
    // Model the typed array as readonly for safety in types, but perform an
    // intentional in-place wipe below. Place a narrow eslint-disable directly
    // on the assignment to avoid broad/unused disables elsewhere in the file.
    const ta = typedArray as unknown as {
      readonly length: number;
      readonly [index: number]: bigint;
    };

    // eslint-disable-next-line functional/no-let -- loop counter required for BigInt wipe
    for (let i = 0; i < ta.length; i++) {
      // eslint-disable-next-line functional/immutable-data,functional/prefer-readonly-type -- intentional in-place wipe of BigInt typed array for security
      (ta as unknown as { [index: number]: bigint })[i] = 0n;
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

  // eslint-disable-next-line functional/no-let, functional/immutable-data -- loop counter and in-place wipe required for secure zeroing
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
 * Execute a callback with a transient secure buffer that is wiped on return.
 * Recommended for short-lived secrets to enforce a safe lifecycle.
 *
 * Example:
 * const result = withSecureBuffer(32, (buf) => {
 *   // use buf; it will be wiped on return, including on throw
 * });
 */
export function withSecureBuffer<T>(
  length: number,
  fn: (buf: Uint8Array) => T,
): T {
  validateNumericParam(length, "length", 1, 4096);
  const buf = new Uint8Array(length);
  try {
    return fn(buf);
  } finally {
    try {
      secureWipe(buf);
    } catch {
      /* best-effort wipe */
    }
  }
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

  // eslint-disable-next-line functional/no-let -- mutable lifecycle flag for secure buffer
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

  // eslint-disable-next-line functional/no-let -- accumulator for constant-time compare
  let diff = 0;

  // eslint-disable-next-line functional/no-let -- loop counter for fixed-length compare
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
  // eslint-disable-next-line functional/no-let -- accumulator for constant-time array compare
  let diff = 0;
  const len = Math.max(ua.length, ub.length, MIN_COMPARE_BYTES);
  // eslint-disable-next-line functional/no-let -- loop counter for array comparison
  for (let i = 0; i < len; i++) {
    const ca = ua[i] ?? 0;
    const cb = ub[i] ?? 0;
    diff |= ca ^ cb;
  }
  return diff === 0 && ua.length === ub.length;
}

/**
 * Performs a constant-time comparison of two byte arrays.
 * This is the recommended function when you already operate on bytes (UTF-8, binary keys).
 * It runs in time proportional to max(len(a), len(b), MIN_COMPARE_BYTES).
 */
export function secureCompareBytes(a: Uint8Array, b: Uint8Array): boolean {
  return compareUint8Arrays(a, b);
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
    return await compareWithCrypto(sa, sb, options);
  } catch (error) {
    return handleCompareError(error, sa, sb, options);
  }
}

// Extracted helper to reduce cognitive complexity of secureCompareAsync
async function compareWithCrypto(
  sa: string,
  sb: string,
  options?: { readonly requireCrypto?: boolean },
): Promise<boolean> {
  const { subtle } = await checkCryptoAvailability(options);

  // eslint-disable-next-line functional/no-let -- temporary buffers created and wiped in finally
  let ua: Uint8Array | undefined;
  // eslint-disable-next-line functional/no-let -- temporary buffers created and wiped in finally
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
    if (ua) secureWipe(ua);
    if (ub) secureWipe(ub);
  }
}

function handleCompareError(
  error: unknown,
  sa: string,
  sb: string,
  options?: { readonly requireCrypto?: boolean },
): boolean {
  const strict = options?.requireCrypto === true || isSecurityStrict();
  if (error instanceof CryptoUnavailableError) {
    if (strict) throw error;
    return secureCompare(sa, sb);
  }
  if (strict) {
    // Normalize to a consistent error type in strict mode
    throw new CryptoUnavailableError(
      "Cryptographic compare failed in strict mode.",
    );
  }
  if (isDevelopment()) {
    secureDevLog(
      "error",
      "secureCompareAsync",
      "Crypto compare failed; falling back",
      { error: sanitizeErrorForLogs(error) },
    );
  }
  safeEmitMetric("secureCompare.fallback", 1, {
    requireCrypto: String(!!options?.requireCrypto),
    subtlePresent: "unknown",
    strict: strict ? "1" : "0",
  });
  return secureCompare(sa, sb);
}

// --- Safe Logging & Redaction ---

/** Maximum recursion depth for the redaction function. */
export const MAX_REDACT_DEPTH = 8;
/** Maximum length of a string in logs before it is truncated. */
export const MAX_LOG_STRING = 8192;

// NEW: Breadth limits to complement depth caps
const MAX_KEYS_PER_OBJECT = 64;
const MAX_ITEMS_PER_ARRAY = 128;

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
  const entriesSource = Object.entries(object).filter(
    ([key]) =>
      key !== "__proto__" && key !== "prototype" && key !== "constructor",
  );
  // Filter and process keys while avoiding inclusion of unsafe key names.
  // Keys that don't match SAFE_KEY_REGEX are counted and not included in
  // the resulting object to prevent accidental leakage of internal or
  // sensitive key identifiers. We still redact values for known sensitive
  // keys when the name is safe.
  // eslint-disable-next-line functional/no-let -- intentional mutable counter for unsafe key count
  let unsafeCount = 0;
  const loggingCfg = getLoggingConfig();
  const includeHashes =
    !environment.isProduction &&
    loggingCfg.allowUnsafeKeyNamesInDev &&
    loggingCfg.includeUnsafeKeyHashesInDev;
  // mutable on-purpose for collecting dev-only hashes
  // eslint-disable-next-line functional/no-let -- collecting dev-only hashes in a local mutable
  let unsafeHashes: readonly string[] = [];
  const result = entriesSource.reduce(
    (acc, [key, rawValue]) => {
      if (!SAFE_KEY_REGEX.test(key)) {
        unsafeCount += 1;
        if (includeHashes) {
          try {
            // Non-blocking best-effort: compute a SHA-256 hex digest of
            // the key + optional salt. Use the synchronous JS-only hasher
            // as a fallback to avoid introducing runtime crypto failures.
            const salt = loggingCfg.unsafeKeyHashSalt ?? "";
            const input = `${salt}:${key}`;
            // Use builtin subtle if available; otherwise fallback to a
            // simple JS-based hash (not cryptographically strong) to
            // maintain deterministic debug output in development.
            // Compute a deterministic, synchronous, non-crypto hash (DJB2)
            // for development-only debugging. This avoids any possibility
            // of emitting raw key names or relying on async subtle.digest
            // inside a sync code path.
            // eslint-disable-next-line functional/no-let -- intentional local loop counter for DJB2
            let h = 5381;
            // eslint-disable-next-line functional/no-let -- loop counter
            for (let i = 0; i < input.length; i++) {
              /* intentional bitwise ops for DJB2 */
              h = ((h << 5) + h) ^ input.charCodeAt(i);
            }
            // Normalize to hex string; append immutably to avoid mutating shared
            // arrays while still keeping this local, development-only collection.
            unsafeHashes = [...unsafeHashes, (h >>> 0).toString(16)];
          } catch {
            /* ignore hashing failures in dev */
          }
        }
        return acc;
      }

      if (isSensitiveKey(key)) return { ...acc, [key]: REDACTED_VALUE };

      const v: unknown = (() => {
        if (typeof rawValue === "string") return _redactPrimitive(rawValue);
        if (rawValue && typeof rawValue === "object")
          return _redact(rawValue, depth + 1);
        return rawValue;
      })();

      return { ...acc, [key]: v };
    },
    Object.create(null) as Record<string, unknown>,
  );

  if (unsafeCount > 0) {
    // Include a count rather than the actual unsafe keys to avoid key-name leakage.
    const baseOut: Record<string, unknown> = {
      ...result,
      __unsafe_key_count__: unsafeCount,
    };
    return unsafeHashes.length > 0
      ? { ...baseOut, ["__unsafe_key_hashes__"]: unsafeHashes.slice(0, 32) }
      : baseOut;
  }

  return result;
}

function _cloneAndNormalizeForLogging(
  data: unknown,
  depth: number,

  visited: ReadonlySet<unknown>,
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

  // Create a new Set for this recursion branch without mutating the caller's set
  const branchVisited = new Set([...visited, data]);
  return handleSpecialObjectTypes(data, depth, branchVisited);
}

/**
 * Handles special object types for logging normalization.
 */
function handleSpecialObjectTypes(
  data: object,
  depth: number,

  visited: ReadonlySet<unknown>,
): unknown {
  // NEW: Opaque handling for Map/Set to avoid leaking entries
  try {
    if (data instanceof Map) {
      return {
        __type: "Map",
        size: data.size,
        __redacted: true,
        reason: "content-not-logged",
      };
    }
    if (data instanceof Set) {
      return {
        __type: "Set",
        size: data.size,
        __redacted: true,
        reason: "content-not-logged",
      };
    }
  } catch {
    // ignore prototype trickery; fall through to other handlers
  }

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

  visited: ReadonlySet<unknown>,
): unknown {
  // NEW: breadth limiting
  const limit = Math.min(MAX_ITEMS_PER_ARRAY, Math.max(0, data.length));
  /* eslint-disable functional/prefer-readonly-type -- mutable array for building result */
  const out: unknown[] = [];
  /* eslint-enable functional/prefer-readonly-type */
  // eslint-disable-next-line functional/no-let -- intentional loop counter for array breadth processing
  for (let i = 0; i < limit; i++) {
    /* eslint-disable functional/immutable-data -- intentional push to build array */
    out.push(_cloneAndNormalizeForLogging(data[i], depth + 1, visited));
    /* eslint-enable functional/immutable-data */
  }
  if (data.length > limit) {
    /* eslint-disable functional/immutable-data -- intentional push for truncation summary */
    out.push({
      __truncated: true,
      originalCount: data.length,
      displayedCount: limit,
    });
    /* eslint-enable functional/immutable-data */
  }
  return out;
}

/**
 * Handles plain objects for logging.
 */
function handlePlainObject(
  data: object,
  depth: number,

  visited: ReadonlySet<unknown>,
): unknown {
  const result = Object.create(null) as Record<string, unknown>;

  // NEW: count symbol keys without exposing them
  try {
    const symCount = Object.getOwnPropertySymbols?.(data)?.length ?? 0;
    if (symCount > 0) {
      // eslint-disable-next-line functional/immutable-data
      result["__symbol_key_count__"] = symCount;
    }
  } catch {
    // ignore
  }

  const allKeys = Object.keys(data).filter(
    (k) => k !== "__proto__" && k !== "prototype" && k !== "constructor",
  );
  // NEW: breadth limiting for keys
  const limit = Math.min(MAX_KEYS_PER_OBJECT, Math.max(0, allKeys.length));
  /* eslint-disable functional/no-let -- loop counter for key processing */
  for (let i = 0; i < limit; i++) {
    const key = allKeys[i]!;
    try {
      // eslint-disable-next-line functional/immutable-data
      result[key] = _cloneAndNormalizeForLogging(
        (data as Record<string, unknown>)[key],
        depth + 1,
        visited,
      );
    } catch {
      // eslint-disable-next-line functional/immutable-data
      result[key] = { __redacted: true, reason: "getter-threw" };
    }
  }
  /* eslint-enable functional/no-let */
  if (allKeys.length > limit) {
    // eslint-disable-next-line functional/immutable-data
    result["__additional_keys__"] = {
      __truncated: true,
      originalCount: allKeys.length,
      displayedCount: limit,
    };
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

// ADD: Central sanitizer for log message strings using the same primitives as context redaction.
export function sanitizeLogMessage(message: unknown): string {
  try {
    // Normalize to string early
    const asString = typeof message === "string" ? message : String(message);

    // Replace sensitive patterns with [REDACTED] while preserving the rest of the message
    // 1) Remove JWT-like tokens using a pre-audited safe pattern
    // 2) Redact common key=value secrets with a linear-time, anchored pattern (no nested quantifiers)
    // 3) Redact Authorization header or bearer tokens conservatively
    const sanitized = asString
      // JWT-like structures
      .replace(JWT_LIKE_REGEX, REDACTED_VALUE)
      // key=value pairs such as password=..., token:..., secret=...
      .replace(
        /\b(password|pass|token|secret|jwt|authorization)\s*[:=]\s*[^\s,;&]{1,2048}/gi,
        "$1=[REDACTED]",
      )
      // Authorization headers or bearer tokens anywhere in the string
      .replace(/\b(authorization)\s*[:=]\s*[^\r\n]{1,2048}/gi, "$1=[REDACTED]")
      .replace(/\b(bearer)\s+[\w.~+/-]{1,2048}=*/gi, "$1 [REDACTED]");

    // Enforce max length
    return _truncateIfLong(sanitized);
  } catch {
    // Fail-closed on sanitizer errors
    return REDACTED_VALUE;
  }
}

// ADD: Guard component names to a safe subset to prevent accidental leakage.
export function sanitizeComponentName(name: unknown): string {
  try {
    // Only accept strings, reject other types
    if (typeof name !== "string") {
      return "unsafe-component-name";
    }
    return SAFE_KEY_REGEX.test(name) ? name : "unsafe-component-name";
  } catch {
    return "unsafe-component-name";
  }
}

// --- Dev log rate limiting (development only) ---
// Keep this small and auditable to satisfy Hardened Simplicity.
const DEV_LOG_TOKENS = 200; // Max logs per minute in dev

// Use a single const state object to avoid `let`; mutations are localized and audited.
/* eslint-disable functional/prefer-readonly-type -- audited mutable state for rate limiting */
const devLogState: {
  bucket: number;
  lastRefill: number;
  dropped: number;
  lastDropReport: number;
} = {
  bucket: DEV_LOG_TOKENS,
  lastRefill: Date.now(),
  dropped: 0,
  lastDropReport: 0,
};
/* eslint-enable functional/prefer-readonly-type */

function devLogAllow(): boolean {
  if (environment.isProduction) return false;
  const now = Date.now();
  const loggingCfg = getLoggingConfig();
  const tokensPerMinute = loggingCfg.rateLimitTokensPerMinute ?? DEV_LOG_TOKENS;

  // If the configured tokens-per-minute is lower than the current bucket,
  // clamp the bucket immediately so tests or runtime config changes take
  // effect without waiting for the next refill window.
  // This keeps the behaviour simple and auditable.
  if (devLogState.bucket > Math.max(0, Math.trunc(tokensPerMinute))) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    devLogState.bucket = Math.max(0, Math.trunc(tokensPerMinute));
  }

  // Refill bucket once per minute using configured tokens
  if (now - devLogState.lastRefill >= 60_000) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    devLogState.bucket = Math.max(1, Math.trunc(tokensPerMinute));
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    devLogState.lastRefill = now;
  }
  if (devLogState.bucket > 0) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    devLogState.bucket--;
    return true;
  }

  // Track dropped and occasionally emit a summary (no recursion into our logger)
  // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
  devLogState.dropped++;
  if (now - devLogState.lastDropReport > 5_000) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    devLogState.lastDropReport = now;
    try {
      // Do NOT call secureDevLog here; go straight to console
      // Avoid including user context; share only counts

      console.warn(
        "[security-kit] dev log rate-limit: dropping",
        devLogState.dropped,
        "messages in the last 5s window",
      );
      // Emit telemetry for rate hits
      try {
        safeEmitMetric("logRateLimit.hit", devLogState.dropped, {
          reason: "dev",
        });
      } catch {
        /* ignore telemetry failures */
      }
      // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
      devLogState.dropped = 0;
    } catch {
      // ignore console errors in exotic environments
    }
  }
  return false;
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
  // Serialize a string-safe representation of the context to avoid leaking structured data
  const ctxString = ((): string => {
    try {
      // Use an untyped JS replacer to avoid explicit `any` annotations while
      // keeping a simple length truncation for string values. This local
      // function is intentionally narrow and used only for serializing
      // dev-only log context.
      /**
       * JSON replacer used only for dev logging string truncation.
       * @param _k The key (ignored).
       * @param v The value to process.
       */
      function replacer(_k: string, v: unknown): unknown {
        return typeof v === "string" && v.length > 1024
          ? `${v.slice(0, 1024)}...[TRUNC]`
          : v;
      }
      return JSON.stringify(safeContext, replacer);
    } catch {
      return String(safeContext);
    }
  })();
  // DEFENSE-IN-DEPTH: sanitize message at the sink, even if caller already sanitized.
  const safeMessage = sanitizeLogMessage(message);

  const out = ctxString ? `${safeMessage} | context=${ctxString}` : safeMessage;
  switch (level) {
    case "debug":
      console.debug(out);
      break;
    case "info":
      console.info(out);
      break;
    case "warn":
      console.warn(out);
      break;
    case "error":
      console.error(out);
      break;
    default:
      console.info(out);
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
  // Apply rate limit before any work (redaction, event dispatch, stringify)
  if (!devLogAllow()) return;

  // NEW: enforce safe component and sanitize the message string
  const safeComponent = sanitizeComponentName(component);
  const safeMessage = sanitizeLogMessage(message);

  const safeContext = _redact(context);
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    component: safeComponent,
    message: safeMessage,
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

  const message_ = `[${logEntry.level}] (${safeComponent}) ${safeMessage}`;
  _devConsole(level, message_, safeContext);
}

// Set the logger for the dev-logger facade (moved to lazy initialization)
// This is now done lazily to avoid side effects on import
// setDevLogger(secureDevLog);

// Provide descriptive compatibility aliases for consumers that prefer
// more explicit names. These are simple re-exports and preserve behavior.
export const secureDevelopmentLog = secureDevLog;
export const setDevelopmentLogger = setDevelopmentLogger_;

// --- Internal Utilities ---
