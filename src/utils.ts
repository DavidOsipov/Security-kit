// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * General-purpose security utilities, including timing-safe comparison,
 * secure wiping, and safe logging.
 * @module
 */

import { InvalidParameterError } from "./errors";
import { ensureCrypto } from "./state";
import { environment, isDevelopment } from "./environment";

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
export function secureWipe(
  typedArray: ArrayBufferView | null | undefined,
): void {
  if (!typedArray) return;
  if (isDevelopment() && typedArray.byteLength > 1024) {
    secureDevLog(
      "warn",
      "secureWipe",
      "Wiping a large buffer (>1KB). Prefer non-extractable CryptoKey objects.",
    );
  }
  try {
    if (
      typeof BigUint64Array !== "undefined" &&
      typedArray instanceof BigUint64Array
    ) {
      (typedArray as BigUint64Array).fill(0n);
      return;
    }
    if (
      typeof BigInt64Array !== "undefined" &&
      typedArray instanceof BigInt64Array
    ) {
      (typedArray as BigInt64Array).fill(0n);
      return;
    }
    if (typeof (typedArray as Uint8Array).fill === "function") {
      (typedArray as Uint8Array).fill(0);
      return;
    }
    const view = new Uint8Array(
      typedArray.buffer,
      typedArray.byteOffset,
      typedArray.byteLength,
    );
    view.fill(0);
  } catch {
    /* best-effort */
  }
}

// --- Timing-Safe Comparison ---
const MAX_COMPARISON_LENGTH = 4096;
const ENCODER = new TextEncoder();

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
): Promise<boolean> {
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
      secureDevLog(
        "warn",
        "security-kit",
        "SubtleCrypto unavailable; falling back to sync compare",
      );
      return secureCompare(sa, sb);
    }
    const digestFor = (str: string) =>
      subtle.digest("SHA-256", ENCODER.encode(str));
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
export function sanitizeErrorForLogs(
  err: unknown,
): { name: string; message: string } | undefined {
  if (!(err instanceof Error)) return undefined;
  return { name: err.name, message: String(err.message).slice(0, 512) };
}

export function _redact(data: unknown, depth = 0): unknown {
  const MAX_DEPTH = 8;
  const SECRET_KEY_REGEX =
    /token|secret|password|pass|auth|key|bearer|session|credential|jwt|signature|cookie|private|cert/i;
  const JWT_LIKE_REGEX = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}$/;
  const REDACTED_VALUE = "[REDACTED]";
  const SAFE_KEY_REGEX = /^[\w.-]{1,64}$/;

  if (depth >= MAX_DEPTH) return "[REDACTED_MAX_DEPTH]";
  if (data === null || typeof data !== "object") {
    if (typeof data === "string" && JWT_LIKE_REGEX.test(data))
      return REDACTED_VALUE;
    return data;
  }
  if (Array.isArray(data)) return data.map((item) => _redact(item, depth + 1));

  const out: Record<string, unknown> = Object.create(null);
  for (const [key, rawVal] of Object.entries(data as Record<string, unknown>)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor")
      continue;
    if (SECRET_KEY_REGEX.test(key)) {
      out[key] = REDACTED_VALUE;
      continue;
    }
    if (!SAFE_KEY_REGEX.test(key)) continue;
    out[key] = _redact(rawVal, depth + 1);
  }
  return out;
}

export function secureDevLog(
  level: "debug" | "info" | "warn" | "error",
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

/** @deprecated Use `secureDevLog` instead. */
export function secureDevNotify(
  type: "debug" | "info" | "warn" | "error",
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
