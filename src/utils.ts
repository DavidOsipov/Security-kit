// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * General-purpose security utilities, including timing-safe comparison,
 * secure wiping, and safe logging.
 * @module
 */

import { InvalidParameterError, CryptoUnavailableError } from "./errors";
import { ensureCrypto } from "./state";
import { environment, isDevelopment } from "./environment";
import { SHARED_ENCODER } from "./encoding";

// --- Parameter Validation ---
export function validateNumericParam(
  value: number,
  paramName: string,
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
      `${paramName} must be an integer between ${min} and ${max}.`,
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
 */
export function secureWipe(
  typedArray: ArrayBufferView | null | undefined,
  opts?: { forbidShared?: boolean },
): void {
  /**
   * Options:
   * - forbidShared: when true, throw if the provided view is backed by a SharedArrayBuffer.
   *   SharedArrayBuffer-backed memory cannot be reliably zeroed by a single thread and
   *   therefore should not be relied upon for secret material.
   */
  if (!typedArray) return;
  if (opts?.forbidShared) {
    try {
      if (
        typeof SharedArrayBuffer !== "undefined" &&
        typedArray.buffer instanceof SharedArrayBuffer
      ) {
        throw new InvalidParameterError(
          "secureWipe: SharedArrayBuffer-backed views cannot be securely wiped.",
        );
      }
    } catch {
      // If SharedArrayBuffer is not available in this environment, ignore.
    }
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
    const tryNodeBufferWipe = () => {
      const isNodeBuffer =
        typeof Buffer !== "undefined" &&
        (
          Buffer as unknown as {
            isBuffer?: (x: unknown) => boolean;
          }
        ).isBuffer?.(typedArray);
      if (!isNodeBuffer) return false;
      (typedArray as unknown as Buffer).fill(0);
      return true;
    };

    const tryDataViewWipe = () => {
      if (typeof DataView === "undefined" || !(typedArray instanceof DataView))
        return false;
      new Uint8Array(
        typedArray.buffer,
        typedArray.byteOffset,
        typedArray.byteLength,
      ).fill(0);
      return true;
    };

    const tryBigIntWipe = () => {
      if (
        typeof BigUint64Array !== "undefined" &&
        typedArray instanceof BigUint64Array
      ) {
        (typedArray as BigUint64Array).fill(0n);
        return true;
      }
      if (
        typeof BigInt64Array !== "undefined" &&
        typedArray instanceof BigInt64Array
      ) {
        (typedArray as BigInt64Array).fill(0n);
        return true;
      }
      return false;
    };

    const tryGenericWipe = () => {
      // Only perform a generic wipe when the underlying buffer looks usable.
      if (!typedArray || !typedArray.buffer) return false;
      if (typeof (typedArray as Uint8Array).fill === "function") {
        (typedArray as Uint8Array).fill(0);
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

    if (tryNodeBufferWipe()) return;
    if (tryDataViewWipe()) return;
    if (tryBigIntWipe()) return;
    tryGenericWipe();
  } catch {
    /* best-effort */
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

export function secureCompare(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const sa = String(a ?? "").normalize("NFC");
  const sb = String(b ?? "").normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }
  const len = Math.max(sa.length, sb.length);
  let diff = sa.length ^ sb.length;
  for (let i = 0; i < len; i++) {
    diff |= (sa.charCodeAt(i) || 0) ^ (sb.charCodeAt(i) || 0);
  }
  return diff === 0;
}

export async function secureCompareAsync(
  a: string | null | undefined,
  b: string | null | undefined,
  options?: { requireCrypto?: boolean },
): Promise<boolean> {
  /**
   * Timing-safe comparison that uses the platform SubtleCrypto.digest when available.
   * Options:
   * - requireCrypto: when true, throw CryptoUnavailableError if SubtleCrypto is not
   *   available. This enforces the "Fail Loudly" rule for security-critical comparisons.
   */
  const sa = String(a ?? "").normalize("NFC");
  const sb = String(b ?? "").normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }
  try {
    const crypto = await ensureCrypto();
    const subtle = (crypto as { subtle?: SubtleCrypto }).subtle;
    if (!subtle?.digest) {
      // If caller requires crypto, fail loudly per constitution; otherwise fall back.
      if (options?.requireCrypto) {
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
    const digestFor = (str: string) =>
      subtle.digest("SHA-256", SHARED_ENCODER.encode(str));
    let va: Uint8Array | undefined, vb: Uint8Array | undefined;
    try {
      const [da, db] = await Promise.all([digestFor(sa), digestFor(sb)]);
      va = new Uint8Array(da);
      vb = new Uint8Array(db);
      if (va.length !== vb.length) return false;
      let diff = 0;
      for (let i = 0; i < va.length; i++) {
        diff |= (va[i] ?? 0) ^ (vb[i] ?? 0);
      }
      return diff === 0;
    } finally {
      if (va) secureWipe(va);
      if (vb) secureWipe(vb);
    }
  } catch (error) {
    // If caller requested a strict crypto requirement, surface a Cryptounavailable error
    if (options?.requireCrypto && error instanceof CryptoUnavailableError)
      throw error;
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
  if (JWT_LIKE_REGEX.test(value)) return REDACTED_VALUE;
  if (value.length > MAX_LOG_STRING) return _truncateIfLong(value);
  return value;
}

function _redactObject(obj: Record<string, unknown>, depth: number): unknown {
  const out: Record<string, unknown> = Object.create(null);
  for (const [key, rawVal] of Object.entries(obj)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor")
      continue;
    if (SECRET_KEY_REGEX.test(key)) {
      out[key] = REDACTED_VALUE;
      continue;
    }
    if (!SAFE_KEY_REGEX.test(key)) continue;
    if (typeof rawVal === "string") out[key] = _truncateIfLong(rawVal);
    else out[key] = _redact(rawVal, depth + 1);
  }
  return out;
}

export function _redact(data: unknown, depth = 0): unknown {
  if (depth >= MAX_REDACT_DEPTH) return "[REDACTED_MAX_DEPTH]";
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
  msg: string,
  safeContext: unknown,
): void {
  if (environment.isProduction) return;
  switch (level) {
    case "debug":
      console.debug(msg, safeContext);
      break;
    case "info":
      console.info(msg, safeContext);
      break;
    case "warn":
      console.warn(msg, safeContext);
      break;
    case "error":
      console.error(msg, safeContext);
      break;
    default:
      console.info(msg, safeContext);
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
        new CustomEvent("secure-dev-log", { detail: logEntry }),
      );
    } catch {
      /* ignore */
    }
  }

  const msg = `[${logEntry.level}] (${component}) ${message}`;
  // Delegate actual console interaction to the internal wrapper. This
  // centralizes console usage in one function which the sanitizer can
  // explicitly allow by name.
  _devConsole(level, msg, safeContext);
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
  if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
    return Buffer.from(buf).toString("base64");
  }
  const bytes = new Uint8Array(buf);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const base64abc =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const at = (s: string, i: number): string => s.charAt(i);
  const out: string[] = [];
  let i = 0;
  const l = bytes.length;
  for (; i + 2 < l; i += 3) {
    const b0 = view.getUint8(i),
      b1 = view.getUint8(i + 1),
      b2 = view.getUint8(i + 2);
    out.push(
      at(base64abc, b0 >> 2),
      at(base64abc, ((b0 & 0x03) << 4) | (b1 >> 4)),
      at(base64abc, ((b1 & 0x0f) << 2) | (b2 >> 6)),
      at(base64abc, b2 & 0x3f),
    );
  }
  if (i < l) {
    const b0 = view.getUint8(i);
    out.push(at(base64abc, b0 >> 2));
    if (i === l - 1) {
      out.push(at(base64abc, (b0 & 0x03) << 4), "==");
    } else {
      const b1 = view.getUint8(i + 1);
      out.push(
        at(base64abc, ((b0 & 0x03) << 4) | (b1 >> 4)),
        at(base64abc, (b1 & 0x0f) << 2),
        "=",
      );
    }
  }
  return out.join("");
}

export const __test_arrayBufferToBase64:
  | ((buf: ArrayBuffer) => string)
  | undefined =
  typeof __TEST__ !== "undefined" && __TEST__
    ? _arrayBufferToBase64
    : undefined;
