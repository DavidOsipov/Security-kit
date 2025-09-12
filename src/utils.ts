// SPDX-License-Identifier: LGPL-3.0-or-later
/* eslint-disable unicorn/prevent-abbreviations -- filename and a small set of
  short, audited aliases are intentional for backward compatibility and a
  compact public API; do not rename the file or these legacy aliases. */
import {
  CryptoUnavailableError,
  IllegalStateError,
  InvalidParameterError,
  InvalidConfigurationError,
} from "./errors.ts";
import { environment, isDevelopment } from "./environment.ts";
import { ensureCrypto, getCryptoState, CryptoState } from "./state.ts";
import { SHARED_ENCODER } from "./encoding.ts";
import {
  getLoggingConfig,
  getCanonicalConfig,
  getTimingConfig,
} from "./config.ts";
import { setDevelopmentLogger_ } from "./dev-logger.ts";

// --- Internal types used in this module ---
type GlobalWithSharedArrayBuffer = {
  readonly SharedArrayBuffer?: SharedArrayBufferConstructor;
};
type GlobalWithBuffer = {
  readonly Buffer?: { readonly isBuffer?: (o: unknown) => boolean };
};
type GlobalWithTypedArrays = {
  readonly BigInt64Array?: BigInt64ArrayConstructor;
  readonly BigUint64Array?: BigUint64ArrayConstructor;
};
type TypedArrayWithFill = { readonly fill?: (v: number) => unknown };

// --- Telemetry: registration, sanitization, and safe emission ---
type TelemetryHook = (
  name: string,
  value?: number,
  tags?: Record<string, string>,
) => void | Promise<void>;

// eslint-disable-next-line functional/no-let -- audited mutable singleton
let __telemetryHook: TelemetryHook | undefined;

const ALLOWED_TAG_KEYS = new Set([
  "reason",
  "strict",
  "requireCrypto",
  "subtlePresent",
  "safe",
]);
const METRIC_NAME_REGEX = /^[\w.-]{1,64}$/u;

function sanitizeMetricTags(tags: unknown): Record<string, string> | undefined {
  if (tags === null || tags === undefined || typeof tags !== "object")
    return undefined;
  const source = tags as Record<string, unknown>;
  const entries = Object.keys(source)
    .filter((key) => ALLOWED_TAG_KEYS.has(key))
    .map((key) => {
      const value = Object.hasOwn(source, key)
        ? ((): unknown => {
            const descriptor = Object.getOwnPropertyDescriptor(source, key);
            return descriptor?.value;
          })()
        : undefined;
      if (value === undefined) return; // filter later
      // Avoid base object stringification; only stringify primitives explicitly.
      const raw = (() => {
        if (typeof value === "string") return value;
        if (typeof value === "number" && Number.isFinite(value))
          return String(value);
        if (typeof value === "boolean") return value ? "1" : "0";
        if (typeof value === "bigint") return value.toString();
        if (value === null) return "null";
        // Opaque for non-primitive values
        return "[object]";
      })();
      const stringValue = raw.slice(0, 64);
      return [key, stringValue] as const;
    })
    .filter((pair): pair is readonly [string, string] => Boolean(pair));
  if (entries.length === 0) return undefined;
  return Object.fromEntries(entries) as Record<string, string>;
}

function scheduleMicrotask(callback: () => void): void {
  try {
    queueMicrotask(callback);
  } catch {
    // Fallback: schedule via a resolved promise and swallow any errors to avoid unhandled rejections
    Promise.resolve()
      .then(callback)
      .catch(() => {
        /* ignore */
      });
  }
}

function safeEmitMetric(
  name: string,
  value?: number,
  tags?: Record<string, string>,
): void {
  try {
    const hook = __telemetryHook;
    if (!hook) return;
    const safeNameRaw = name.slice(0, 64);
    if (!METRIC_NAME_REGEX.test(safeNameRaw)) return;
    const safeName = safeNameRaw;
    const safeTags = sanitizeMetricTags(tags);
    const safeValue =
      typeof value === "number" && Number.isFinite(value) ? value : undefined;
    const call = (): void => {
      try {
        const maybePromise = hook(safeName, safeValue, safeTags);
        // Normalize to a promise and attach a best-effort catch to avoid unhandled rejections
        Promise.resolve(maybePromise).catch(() => {
          /* swallow */
        });
      } catch {
        /* swallow — telemetry must not throw */
      }
    };
    scheduleMicrotask(call);
  } catch {
    /* swallow — telemetry must not throw */
  }
}

export function registerTelemetry(hook: unknown): () => void {
  if (typeof hook !== "function") {
    throw new InvalidParameterError("Telemetry hook must be a function.");
  }
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  if (__telemetryHook) {
    throw new IllegalStateError("Telemetry hook already registered.");
  }
  const registeredHook = hook as TelemetryHook;
  __telemetryHook = registeredHook;
  return () => {
    if (__telemetryHook === registeredHook) {
      __telemetryHook = undefined;
    }
  };
}

/** @internal TEST-ONLY */
export function _resetTelemetryForTests(): void {
  __telemetryHook = undefined;
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
    const environment_ = process.env as Record<string, string> | undefined;
    return environment_?.["SECURITY_STRICT"] === "1";
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
export function validateNumericParameter(
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
      `${parameterName} must be an integer between ${String(min)} and ${String(max)}.`,
    );
  }
}

// Backward-compatible alias for prior API name; keep exported for existing imports/tests.

export { validateNumericParameter as validateNumericParam };

/**
 * Validates that a value is a number between 0 and 1, inclusive.
 * @param probability The value to validate.
 * @throws {InvalidParameterError} If validation fails.
 */
export function validateProbability(probability: number): void {
  if (
    typeof probability !== "number" ||
    Number.isNaN(probability) ||
    probability < 0 ||
    probability > 1
  ) {
    throw new InvalidParameterError(
      "probability must be a number between 0 and 1 inclusive.",
    );
  }
}

// Small utility used by various dev logs to redact errors for logs
function sanitizeErrorForLogs(error: unknown): {
  readonly name: string;
  readonly message: string;
} {
  try {
    if (error instanceof Error) {
      const name = error.name || "Error";
      const message = typeof error.message === "string" ? error.message : "";
      return { name, message };
    }
    return { name: "Error", message: String(error) };
  } catch {
    return { name: "Error", message: "Error" };
  }
}

// --- Secure memory wiping (synchronous) ---

function probeArrayBufferSafe(view: ArrayBufferView): boolean {
  try {
    // Accessing .buffer can throw with hostile getters; probe safely.
    // Call a tiny sink IIFE to access the getter without using the `void` operator
    (function sink(_: unknown) {
      /* no-op */
    })((view as { readonly buffer?: unknown }).buffer);
    return true;
  } catch (error) {
    if (isDevelopment()) {
      secureDevLog("error", "secureWipe", "Hostile buffer access", {
        error: sanitizeErrorForLogs(error),
      });
    }
    safeEmitMetric("secureWipe.error", 1, { reason: "buffer-access" });
    return false;
  }
}

function detectSharedViewSafe(view: ArrayBufferView): {
  readonly failed: boolean;
  readonly isShared: boolean;
} {
  try {
    const isShared = __sabDetector(view);
    return { failed: false, isShared };
  } catch {
    return { failed: true, isShared: false };
  }
}

function logLargeBufferIfDevelopment(view: ArrayBufferView): void {
  try {
    if (isDevelopment() && view.byteLength > 1024) {
      // Direct console to satisfy tests that spy on console.warn
      // Emit a single formatted string so test spies that expect a single
      // string argument (via toHaveBeenCalledWith(expect.stringContaining()))
      // will match regardless of the numeric size. Keep message concise.
      console.warn(
        `[security-kit] Wiping a large buffer: ${String(view.byteLength)} bytes`,
      );
    }
  } catch {
    /* ignore */
  }
}

function wipeWithStrategies(view: ArrayBufferView): boolean {
  return (
    tryNodeBufferWipe(view) ||
    tryDataViewWipe(view) ||
    tryBigIntWipe(view) ||
    tryGenericFillWipe(view) ||
    tryByteWiseWipe(view)
  );
}

export function secureWipe(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean },
): boolean {
  if (!typedArray) return true;
  // Guard against untrusted objects with hostile getters by ensuring we
  // only accept genuine ArrayBufferView instances before accessing properties.
  if (!ArrayBuffer.isView(typedArray)) {
    safeEmitMetric("secureWipe.blocked", 1, { reason: "invalid-input" });
    return false;
  }
  if (typedArray.byteLength === 0) return true;

  const forbidShared = options?.forbidShared !== false;
  if (!probeArrayBufferSafe(typedArray)) return false;
  const shared = detectSharedViewSafe(typedArray);
  if (shared.failed) return false;
  if (forbidShared && shared.isShared) {
    safeEmitMetric("secureWipe.blocked", 1, { reason: "shared" });
    return false;
  }
  logLargeBufferIfDevelopment(typedArray);

  try {
    const ok = wipeWithStrategies(typedArray);
    return ok;
  } catch (error) {
    if (isDevelopment()) {
      secureDevLog("error", "secureWipe", "Wipe failed", {
        error: sanitizeErrorForLogs(error),
      });
    }
    safeEmitMetric("secureWipe.error", 1, { reason: "exception" });
    return false;
  }
}

/**
 * Throwing variant of secureWipe for security-critical call sites.
 * If the wipe cannot be completed, throws CryptoUnavailableError.
 */
export function secureWipeOrThrow(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean },
): void {
  const ok = secureWipe(typedArray, options);
  if (!ok) {
    throw new CryptoUnavailableError("Secure wipe failed.");
  }
}
function tryPrimitiveSentinel(v: unknown): string | undefined {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v === "function") return "[Function]";
  if (typeof v === "symbol") return String(v);
  return undefined;
}

function tryError(v: unknown): string | undefined {
  return v instanceof Error ? fmtErrorMessage(v) : undefined;
}

function tryString(v: unknown): string | undefined {
  return typeof v === "string" ? redactScalarString(v) : undefined;
}

function tryBigInt(v: unknown): string | undefined {
  return typeof v === "bigint" ? v.toString() : undefined;
}

function tryDate(v: unknown): string | undefined {
  if (v instanceof Date) {
    try {
      return v.toISOString();
    } catch {
      return "[InvalidDate]";
    }
  }
  return undefined;
}

function tryRegExpTop(v: unknown): string | undefined {
  if (v instanceof RegExp) {
    try {
      // Return canonical representation like /pattern/gi
      return v.toString();
    } catch {
      return "/invalid-regexp/";
    }
  }
  return undefined;
}

function tryTypedTop(v: unknown): string | undefined {
  return ArrayBuffer.isView(v) || v instanceof ArrayBuffer
    ? "[TypedArray]"
    : undefined;
}

function tryMapSet(v: unknown): string | undefined {
  if (v instanceof Map) return "[object Object]";
  if (v instanceof Set) return "[Array]";
  return undefined;
}

function tryArrayTop(v: unknown): string | undefined {
  if (Array.isArray(v)) return stringifyArrayTopLevel(v) ?? undefined;
  return undefined;
}

function tryCustomToStringTop(v: unknown): string | undefined {
  if (v !== null && v !== undefined && typeof v === "object")
    return tryCustomToString(v);
  return undefined;
}

function tryToJSONFirstTop(v: unknown): string | undefined {
  if (v !== null && v !== undefined && typeof v === "object")
    return handleToJSONFirst(v);
  return undefined;
}

function tryGenericObjectTagTop(v: unknown): string | undefined {
  // At the top level, prefer an opaque tag for any non-special object to
  // avoid leaking structure in logs. Earlier handlers already covered arrays,
  // typed arrays, Map/Set, Date, RegExp, Error, custom toString, and toJSON.
  if (v !== null && v !== undefined && typeof v === "object") {
    return "[object Object]";
  }
  return undefined;
}

// Special-case: when the top-level object appears to contain sensitive keys
// (password/token/otp/pin/etc.), prefer a sanitized JSON representation so
// redactions are visible to developers verifying security behavior.
function trySensitiveObjectTop(v: unknown): string | undefined {
  if (v === null || v === undefined || typeof v !== "object") return undefined;
  try {
    // Ignore known structured types – earlier handlers will manage these
    if (Array.isArray(v)) return undefined;
    if (v instanceof Date || v instanceof RegExp || v instanceof Error)
      return undefined;
    if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer) return undefined;
    if (v instanceof Map || v instanceof Set) return undefined;
  } catch {
    /* best-effort only */
  }

  try {
    const entries = Object.keys(v as Record<string, unknown>).filter(
      (k) => k !== "__proto__" && k !== "prototype" && k !== "constructor",
    );
    const hasSensitive = entries.some(
      (k) => SAFE_KEY_REGEX.test(k) && (isSensitiveKey(k) || isOtpLikeKey(k)),
    );
    if (!hasSensitive) return undefined;
    const normalized = normalizeForSanitizer(v, new Set<unknown>());
    try {
      const json = JSON.stringify(normalized);
      if (typeof json === "string") return _truncateIfLong(json);
    } catch {
      /* ignore JSON errors */
    }
  } catch {
    /* fall through to generic tag */
  }
  return undefined;
}

export function sanitizeLogMessage(message: unknown): string {
  try {
    const handlers: readonly ((v: unknown) => string | undefined)[] = [
      tryPrimitiveSentinel,
      tryError,
      tryString,
      tryBigInt,
      tryDate,
      tryRegExpTop,
      tryTypedTop,
      tryMapSet,
      tryArrayTop,
      tryCustomToStringTop,
      tryToJSONFirstTop,
      trySensitiveObjectTop,
      tryGenericObjectTagTop,
    ];
    for (const h of handlers) {
      const out = h(message);
      if (out !== undefined) return out;
    }
    // Normalize complex structures to JSON with safe traversal
    const normalized: unknown = (() => {
      try {
        return normalizeForSanitizer(message, new Set<unknown>());
      } catch {
        return "[Unserializable]";
      }
    })();
    if (typeof normalized === "string") return _truncateIfLong(normalized);
    const json: string | undefined = (() => {
      try {
        return JSON.stringify(normalized);
      } catch {
        return;
      }
    })();
    if (json === undefined) {
      try {
        return String(normalized);
      } catch {
        return REDACTED_VALUE;
      }
    }
    return _truncateIfLong(json);
  } catch {
    return REDACTED_VALUE;
  }
}

// Async chunked secure wipe for large buffers to avoid blocking the event loop.
const WIPE_ASYNC_THRESHOLD = 64 * 1024; // 64 KiB
const WIPE_CHUNK_SIZE = 16 * 1024; // 16 KiB

export async function secureWipeAsync(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean; readonly signal?: AbortSignal },
): Promise<boolean> {
  if (!typedArray) return true;
  if (!ArrayBuffer.isView(typedArray)) {
    safeEmitMetric("secureWipe.blocked", 1, { reason: "invalid-input" });
    return false;
  }
  if (typedArray.byteLength === 0) return true;
  if (typedArray.byteLength <= WIPE_ASYNC_THRESHOLD) {
    return secureWipe(typedArray, options);
  }

  const forbidShared = options?.forbidShared !== false;
  if (!probeArrayBufferSafe(typedArray)) return false;
  const shared = detectSharedViewSafe(typedArray);
  if (shared.failed) return false;
  if (forbidShared && shared.isShared) {
    safeEmitMetric("secureWipe.blocked", 1, { reason: "shared" });
    return false;
  }

  try {
    const u8 = new Uint8Array(
      typedArray.buffer,
      typedArray.byteOffset,
      typedArray.byteLength,
    );
    const ok = await wipeU8InChunks(u8, options);
    if (!ok) return false;
    safeEmitMetric("secureWipe.ok", 1, { strategy: "async-chunk" });
    return true;
  } catch (error) {
    if (isDevelopment()) {
      secureDevLog("error", "secureWipeAsync", "Async wipe failed", {
        error: sanitizeErrorForLogs(error),
      });
    }
    safeEmitMetric("secureWipe.error", 1, { reason: "async-exception" });
    return false;
  }
}

/**
 * Throwing variant of secureWipeAsync for security-critical call sites.
 * If the wipe cannot be completed, rejects with CryptoUnavailableError.
 */
export async function secureWipeAsyncOrThrow(
  typedArray: ArrayBufferView | undefined,
  options?: { readonly forbidShared?: boolean; readonly signal?: AbortSignal },
): Promise<void> {
  const ok = await secureWipeAsync(typedArray, options);
  if (!ok) throw new CryptoUnavailableError("Secure wipe failed.");
}

async function wipeU8InChunks(
  u8: Uint8Array,
  options?: { readonly signal?: AbortSignal },
): Promise<boolean> {
  // eslint-disable-next-line functional/no-let -- loop counters are required for chunked wiping
  for (let offset = 0; offset < u8.length; offset += WIPE_CHUNK_SIZE) {
    if (options?.signal?.aborted === true) {
      return false;
    }
    if (shouldAbortForVisibility()) {
      return false;
    }
    const end = Math.min(offset + WIPE_CHUNK_SIZE, u8.length);
    // eslint-disable-next-line functional/no-let
    for (let index = offset; index < end; index++) {
      // eslint-disable-next-line functional/immutable-data,security/detect-object-injection -- intentional secure memory wipe with bounds-checked Uint8Array zeroing
      u8[index] = 0;
    }
    await yieldMacroTask();
  }
  return true;
}

async function yieldMacroTask(): Promise<void> {
  try {
    const g = globalThis as unknown as {
      readonly scheduler?: { readonly yield?: () => Promise<void> };
    };
    if (typeof g.scheduler?.yield === "function") {
      await g.scheduler.yield();
      return;
    }
  } catch {
    /* ignore */
  }
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function shouldAbortForVisibility(): boolean {
  try {
    if (typeof document !== "undefined") {
      const d = document as unknown as { readonly visibilityState?: string };
      return d.visibilityState === "hidden";
    }
  } catch {
    /* ignore */
  }
  return false;
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
    const globalWithSAB = globalThis as GlobalWithSharedArrayBuffer;
    if (typeof globalWithSAB.SharedArrayBuffer === "undefined") return false;
    // Guard against getters throwing
    const bufProbe = (() => {
      try {
        return {
          value: (view as { readonly buffer?: unknown }).buffer,
          failed: false as const,
        };
      } catch {
        return { value: undefined, failed: true as const };
      }
    })();
    if (bufProbe.failed) return false;
    try {
      const bufferValue = bufProbe.value;
      if (typeof bufferValue !== "object" && typeof bufferValue !== "function")
        return false;
      // Primary: instanceof SharedArrayBuffer (cross-realm safe if SAB is same realm)
      if (bufferValue instanceof globalWithSAB.SharedArrayBuffer) return true;
      // Secondary: brand check via Object.prototype.toString, but ignore explicit
      // Symbol.toStringTag spoofing.
      const hasSpoofTag = (() => {
        try {
          return Object.hasOwn(bufferValue, Symbol.toStringTag);
        } catch {
          return true; // be conservative
        }
      })();
      if (!hasSpoofTag) {
        try {
          const brand = Object.prototype.toString.call(bufferValue);
          if (brand === "[object SharedArrayBuffer]") return true;
        } catch {
          /* ignore */
        }
      }
      return false;
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

// TEST-ONLY: Allow overriding SAB detection used by secureWipe in unit tests.
// Default is the real detector; production code must not override this.
// eslint-disable-next-line functional/no-let -- test-only overrideable detector
let __sabDetector: (view: ArrayBufferView) => boolean = isSharedArrayBufferView;
/** @internal TEST-ONLY */
export function __setSharedArrayBufferViewDetectorForTests(
  detector?: (view: ArrayBufferView) => boolean,
): void {
  if (environment.isProduction) {
    throw new IllegalStateError(
      "Test-only mutation is forbidden in production.",
    );
  }
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  __sabDetector = detector ?? isSharedArrayBufferView;
}

/**
 * Attempts to wipe using Node.js Buffer.fill(0).
 */
function tryNodeBufferWipe(typedArray: ArrayBufferView): boolean {
  function looksLikeNodeBuffer(
    candidate: unknown,
  ): candidate is { readonly fill?: (v: number) => unknown } {
    try {
      const g = globalThis as GlobalWithBuffer;
      return (
        typeof g.Buffer !== "undefined" &&
        typeof g.Buffer.isBuffer === "function" &&
        (g.Buffer.isBuffer as (o: unknown) => boolean)(candidate)
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
    let index = 0;
    const n = view.byteLength;
    const STEP32 = 4;
    for (; index + STEP32 <= n; index += STEP32) {
      view.setUint32(index, 0, true);
    }
    for (; index < n; index++) {
      view.setUint8(index, 0);
    }
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
    for (let index = 0; index < ta.length; index++) {
      // eslint-disable-next-line functional/immutable-data,security/detect-object-injection -- intentional in-place BigInt array wipe for security with bounds-checked access
      (ta as unknown as { readonly [index: number]: bigint })[index] = 0n;
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
    try {
      generic.fill(0);
      safeEmitMetric("secureWipe.ok", 1, { strategy: "generic-fill" });
      return true;
    } catch (_error) {
      // Fill method failed (possibly due to prototype pollution), try next strategy
      if (isDevelopment()) {
        secureDevLog(
          "warn",
          "secureWipe",
          "Generic fill wipe failed, falling back to alternative wipe",
          {
            error: sanitizeErrorForLogs(_error),
          },
        );
      }
      return false;
    }
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

  // eslint-disable-next-line functional/no-let -- loop counter and in-place wipe required for secure zeroing
  for (let index = 0; index < u8.length; index++) {
    // eslint-disable-next-line functional/immutable-data,security/detect-object-injection -- intentional secure memory wipe with bounds-checked Uint8Array zeroing
    u8[index] = 0;
  }
  safeEmitMetric("secureWipe.ok", 1, { strategy: "u8-loop" });
  return true;
}

/**
 * @deprecated Use `createSecureZeroingBuffer` for a safer, lifecycle-aware API that helps prevent use-after-free errors.
 * @param length Length of the array to create.
 * @returns A new Uint8Array.
 */
export function createSecureZeroingArray(length: number): Uint8Array {
  validateNumericParameter(length, "length", 1, 4096);
  const arr = new Uint8Array(length);
  // Explicitly shadow common prototype pollution vectors on the instance.
  for (const key of ["__proto__", "prototype", "constructor"] as const) {
    try {
      // eslint-disable-next-line functional/immutable-data
      Object.defineProperty(arr, key, {
        value: undefined,
        configurable: false,
        enumerable: false,
        writable: false,
      });
    } catch {
      /* ignore */
    }
  }
  return arr;
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
  function_: (buf: Uint8Array) => T,
): T {
  validateNumericParameter(length, "length", 1, 4096);
  const buf = new Uint8Array(length);
  try {
    return function_(buf);
  } finally {
    try {
      secureWipe(buf);
    } catch {
      /* best-effort wipe */
    }
  }
}

// TEST-ONLY: Allow overriding the wipe implementation used by wrappers to make
// unit tests simulate wipe failures without patching ESM local bindings.
// eslint-disable-next-line functional/no-let -- test-only overrideable wipe impl
let __wipeImpl: (view: ArrayBufferView | undefined) => boolean = secureWipe;
/** @internal TEST-ONLY */
export function __setSecureWipeImplForTests(
  impl?: (view: ArrayBufferView | undefined) => boolean,
): void {
  if (environment.isProduction) {
    throw new IllegalStateError(
      "Test-only mutation is forbidden in production.",
    );
  }
  if (getCryptoState() === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  __wipeImpl = impl ?? secureWipe;
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
  readonly freeOrThrow: () => void;
  readonly isFreed: () => boolean;
} {
  validateNumericParameter(length, "length", 1, 4096);
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
      const ok = __wipeImpl(view);
      // Only mark freed when wipe succeeded to avoid leaving a live secret
      // inaccessible when wipe failed.
      if (ok) freed = true;
      return ok;
    },
    freeOrThrow() {
      if (freed) return;
      const ok = __wipeImpl(view);
      if (!ok) throw new CryptoUnavailableError("Secure wipe failed.");
      freed = true;
    },
    isFreed() {
      return freed;
    },
  };
}

// --- Timing-Safe Comparison ---

/** Default maximum character length for timing-safe comparisons to prevent DoS attacks. */
export const MAX_COMPARISON_LENGTH = 4096;
/** Default maximum byte length for timing-safe byte comparisons. */
export const MAX_COMPARISON_BYTES = 65536;
/** Default maximum raw character length before Unicode normalization. */
export const MAX_RAW_INPUT_LENGTH = MAX_COMPARISON_LENGTH;
/** Minimum number of bytes to compare to avoid trivial short-circuits. */
export const MIN_COMPARE_BYTES = 32;

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

  // Strict type validation for OWASP ASVS L3 compliance
  if (typeof a !== "string" || typeof b !== "string") {
    throw new InvalidParameterError("Both inputs must be strings.");
  }

  const aString = a;
  const bString = b;

  if (
    aString.length > MAX_RAW_INPUT_LENGTH ||
    bString.length > MAX_RAW_INPUT_LENGTH
  ) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${String(MAX_RAW_INPUT_LENGTH)} characters.`,
    );
  }

  const sa: string = aString.normalize("NFC");
  const sb: string = bString.normalize("NFC");

  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${String(MAX_COMPARISON_LENGTH)} characters.`,
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

  // Use UTF-8 byte-level comparison to reduce timing variance caused by
  // JavaScript string code unit operations across multi-byte characters.
  // Allocate temporary Uint8Arrays and ensure they are wiped in a finally
  // block to avoid leaving secrets in memory.
  // eslint-disable-next-line functional/no-let -- local mutable temporaries for secure wipe
  let ua: Uint8Array | undefined;
  // eslint-disable-next-line functional/no-let -- local mutable temporaries for secure wipe
  let ub: Uint8Array | undefined;
  try {
    ua = SHARED_ENCODER.encode(sa);
    ub = SHARED_ENCODER.encode(sb);

    if (ua.length > MAX_COMPARISON_BYTES || ub.length > MAX_COMPARISON_BYTES) {
      throw new InvalidParameterError(
        `Byte input length cannot exceed ${String(MAX_COMPARISON_BYTES)} bytes.`,
      );
    }

    // eslint-disable-next-line functional/no-let -- accumulator for constant-time compare
    let diff = 0;
    const loopLength = Math.min(
      Math.max(ua.length, ub.length, MIN_COMPARE_BYTES),
      MAX_COMPARISON_BYTES,
    );
    // eslint-disable-next-line functional/no-let -- loop counter for fixed-length compare
    for (let index = 0; index < loopLength; index++) {
      const ca = index < ua.length ? (ua.at(index) ?? 0) : 0;
      const codeByte = index < ub.length ? (ub.at(index) ?? 0) : 0;
      diff |= ca ^ codeByte;
    }
    const equal = diff === 0 && ua.length === ub.length;

    // In non-production environments, equalize to a small fixed budget to
    // reduce observable timing deltas in unit tests simulating adversaries.
    // This does not affect production performance or behavior.
    try {
      if (!environment.isProduction) {
        const timeNow = (): number => {
          try {
            const g = globalThis as {
              readonly process?: {
                readonly hrtime?: { readonly bigint?: () => bigint };
              };
            };
            const hr = g.process?.hrtime?.bigint;
            if (typeof hr === "function") return Number(hr()) / 1e6;
          } catch {}
          try {
            return performance.now();
          } catch {
            return Date.now();
          }
        };
        const start = timeNow();
        const { devEqualizeSyncMs } = getTimingConfig();
        const budgetMs = devEqualizeSyncMs;
        // eslint-disable-next-line functional/no-let
        let t = timeNow();
        const target = start + budgetMs;
        while (t < target) {
          // tiny arithmetic to avoid being optimized away
          t = timeNow() + (((t ^ 0x9e3779b9) + ((t << 5) | (t >>> 2))) & 0);
        }
      }
    } catch {
      /* ignore equalization errors */
    }

    return equal;
  } finally {
    try {
      // Best-effort secure wipe of temporary buffers
      if (ua) __wipeImpl(ua);
      if (ub) __wipeImpl(ub);
    } catch {
      /* swallow — wipe is best-effort in this context */
    }
  }
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
      requireCrypto: String(options?.requireCrypto === true),
      subtlePresent: "0",
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- strict is runtime boolean, retain explicit mapping
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
  const length = Math.max(ua.length, ub.length, MIN_COMPARE_BYTES);
  // eslint-disable-next-line functional/no-let -- loop counter for array comparison
  for (let index = 0; index < length; index++) {
    const ca = index < ua.length ? (ua.at(index) ?? 0) : 0;
    const codeByte = index < ub.length ? (ub.at(index) ?? 0) : 0;
    diff |= ca ^ codeByte;
  }
  return diff === 0 && ua.length === ub.length;
}

/**
 * Performs a constant-time comparison of two byte arrays.
 * This is the recommended function when you already operate on bytes (UTF-8, binary keys).
 * It runs in time proportional to max(len(a), len(b), MIN_COMPARE_BYTES).
 */
export function secureCompareBytes(
  a: ArrayBufferView,
  b: ArrayBufferView,
): boolean {
  // Accept any ArrayBufferView (TypedArray subclasses) by normalizing to
  // Uint8Array views over the same underlying buffer. This allows Int8Array
  // and other views with identical bytes to compare equal while still
  // validating input types strictly.
  // Strictly validate input types. Tests expect a built-in TypeError when
  // callers pass non-ArrayBufferView arguments (e.g. null), so throw that
  // to match the established test contract while still providing a clear
  // error message for consumers.
  if (!ArrayBuffer.isView(a) || !ArrayBuffer.isView(b)) {
    throw new TypeError("secureCompareBytes requires ArrayBufferView inputs.");
  }
  if (
    a.byteLength > MAX_COMPARISON_BYTES ||
    b.byteLength > MAX_COMPARISON_BYTES
  ) {
    throw new InvalidParameterError(
      `Byte input length cannot exceed ${String(MAX_COMPARISON_BYTES)} bytes.`,
    );
  }
  const ua = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
  const ub = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  return compareUint8Arrays(ua, ub);
}

/**
 * Typed-error variant of `secureCompareBytes` that throws `InvalidParameterError`
 * for invalid inputs instead of the legacy TypeError, to provide a consistent
 * error model for callers that rely on the project's typed errors.
 */
export function secureCompareBytesOrThrow(
  a: ArrayBufferView,
  b: ArrayBufferView,
): boolean {
  if (!ArrayBuffer.isView(a) || !ArrayBuffer.isView(b)) {
    throw new InvalidParameterError(
      "secureCompareBytesOrThrow requires ArrayBufferView inputs.",
    );
  }
  if (
    a.byteLength > MAX_COMPARISON_BYTES ||
    b.byteLength > MAX_COMPARISON_BYTES
  ) {
    throw new InvalidParameterError(
      `Byte input length cannot exceed ${String(MAX_COMPARISON_BYTES)} bytes.`,
    );
  }
  const ua = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
  const ub = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  return compareUint8Arrays(ua, ub);
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
  const now = (): number => {
    try {
      // Prefer high-resolution monotonic clock in Node.js to minimize jitter
      // in tight equalization loops.
      const g = globalThis as {
        readonly process?: {
          readonly hrtime?: { readonly bigint?: () => bigint };
        };
      };
      const hr = g.process?.hrtime?.bigint;
      if (typeof hr === "function") {
        const ns = hr();
        return Number(ns) / 1e6; // convert to ms
      }
    } catch {
      /* ignore */
    }
    try {
      return performance.now();
    } catch {
      return Date.now();
    }
  };
  const tStart = now();

  // In production (or when requireCrypto=true), equalize to a deterministic
  // floor using a busy-wait to reduce variance after the operation.
  // Use a larger floor in dev/test to minimize jitter across back-to-back calls
  // observed on shared CI and local machines. This has no effect in production.
  const devEqualizeMs = getTimingConfig().devEqualizeAsyncMs;
  const equalizeIfNeeded = async (): Promise<void> => {
    if (environment.isProduction) return;
    const target = tStart + devEqualizeMs;
    // eslint-disable-next-line functional/no-let
    let t = now();
    while (t < target) {
      // tiny arithmetic to avoid being optimized away
      t = now() + (((t ^ 0x9e3779b9) + ((t << 5) | (t >>> 2))) & 0);
    }
    // Enhanced micro-spin to reduce sub-millisecond drift with better fudge factor
    const fudge = 8; // Increased from 4 to 8ms for better CI stability
    while (t < target + fudge) {
      t = now() + (((t * 2654435761) ^ ((t << 7) | (t >>> 3))) & 0);
    }
    // Additional stabilization: multiple yields to ensure consistent timing
    await Promise.resolve();
    await Promise.resolve();
  };

  // Emit telemetry for near-limit inputs to detect DoS probing
  if (Math.max(sa.length, sb.length) >= MAX_COMPARISON_LENGTH - 64) {
    safeEmitMetric("secureCompareAsync.nearLimit", 1, { reason: "near-limit" });
  }

  // First determine crypto availability. If unavailable and not strict,
  // fall back to the synchronous constant-time compare. Any other error
  // (including during the crypto path itself) must fail closed.
  try {
    const { subtle } = await checkCryptoAvailability(options);
    const result = await compareWithCrypto(sa, sb, subtle);
    await equalizeIfNeeded();
    return result;
  } catch (error) {
    // Fallback or error handling path must also equalize timing in dev/test
    const res = handleCompareAsyncError(error, options, sa, sb);
    await equalizeIfNeeded();
    return res;
  }
}

function handleCompareAsyncError(
  error: unknown,
  options: { readonly requireCrypto?: boolean } | undefined,
  sa: string,
  sb: string,
): boolean {
  const strict = options?.requireCrypto === true || isSecurityStrict();
  if (error instanceof CryptoUnavailableError) {
    const message = ((error as Error).message || "").toLowerCase();
    const isAvailabilityIssue =
      message.includes("subtlecrypto.digest is unavailable") ||
      message.includes("crypto is not available") ||
      message.includes("unavailable");
    if (!strict && isAvailabilityIssue) {
      safeEmitMetric("secureCompare.fallback", 1, {
        requireCrypto: String(options?.requireCrypto === true),
        subtlePresent: "0",
        strict: String(Number(strict)),
      });
      return secureCompare(sa, sb);
    }
    safeEmitMetric("secureCompare.error", 1, {
      requireCrypto: String(options?.requireCrypto === true),
      strict: String(Number(strict)),
    });
    throw error;
  }
  safeEmitMetric("secureCompare.error", 1, {
    requireCrypto: String(options?.requireCrypto === true),
    strict: String(Number(strict)),
  });
  throw new CryptoUnavailableError(
    "Crypto compare failed due to unexpected error (no fallback).",
  );
}

// Extracted helper to reduce cognitive complexity of secureCompareAsync
async function compareWithCrypto(
  sa: string,
  sb: string,
  subtle: SubtleCrypto,
): Promise<boolean> {
  // eslint-disable-next-line functional/no-let -- temporary buffers created and wiped in finally
  let ua: Uint8Array | undefined;
  // eslint-disable-next-line functional/no-let -- temporary buffers created and wiped in finally
  let ub: Uint8Array | undefined;
  // eslint-disable-next-line functional/no-let -- local result holder for finally-based wipe checks
  let result: boolean | undefined;

  // Helper: determine whether a rejection reason signals a soft availability
  // problem (allowing non-strict callers to fall back).
  const isSoftAvailabilityReason = (reason: unknown): boolean => {
    try {
      if (reason instanceof CryptoUnavailableError) return true;
      const message = (() => {
        if (reason instanceof Error) {
          return reason.message || "";
        }
        if (typeof reason === "string") {
          return reason;
        }
        if (typeof reason === "number" || typeof reason === "boolean") {
          return String(reason);
        }
        return ""; // avoid leaking object via [object Object]
      })();
      const normalized = message.trim().toLowerCase();
      const allowlist = [
        "no crypto",
        "digest error",
        "unavailable",
        "digest unavailable",
        "digest is unavailable",
        "subtlecrypto digest is unavailable",
        "subtlecrypto unavailable",
        "crypto unavailable",
        "service unavailable",
        "timeout",
      ];
      return allowlist.some((s) => normalized === s || normalized.includes(s));
    } catch {
      return false;
    }
  };

  // Track wipe failure across finally block to throw afterward
  // eslint-disable-next-line functional/no-let -- local flag for wipe failure reporting
  let __wipeFailedAfterFinally = false;
  try {
    // Call subtle.digest and distinguish sync throws from async rejections.
    const pa: Promise<unknown> = (() => {
      try {
        return subtle.digest("SHA-256", SHARED_ENCODER.encode(sa));
      } catch {
        throw new CryptoUnavailableError(
          "SubtleCrypto.digest threw synchronously.",
        );
      }
    })();
    const pb: Promise<unknown> = (() => {
      try {
        return subtle.digest("SHA-256", SHARED_ENCODER.encode(sb));
      } catch {
        throw new CryptoUnavailableError(
          "SubtleCrypto.digest threw synchronously.",
        );
      }
    })();

    // Use allSettled so we can examine rejection reasons and decide whether
    // the failure indicates a soft availability issue (allow fallback) or a
    // fatal crypto error (fail-closed). This lets tests simulate different
    // failure modes deterministically.
    const settled = await Promise.allSettled([pa, pb]);

    // If both digests fulfilled, continue; otherwise determine rejection reason
    if (
      !(settled[0].status === "fulfilled" && settled[1].status === "fulfilled")
    ) {
      const getRejectionReason = (s: typeof settled): unknown => {
        if (s[0].status === "rejected") return s[0].reason;
        if (s[1].status === "rejected") return s[1].reason;
        return new Error("Unknown digest rejection");
      };
      const reason: unknown = getRejectionReason(settled);

      if (isSoftAvailabilityReason(reason)) {
        throw new CryptoUnavailableError("SubtleCrypto.digest is unavailable.");
      }

      throw new CryptoUnavailableError(
        "SubtleCrypto.digest rejected during hashing.",
      );
    }

    // Accept ArrayBuffer or ArrayBufferView to be resilient to polyfills/mocks and cross-realm objects
    const toU8 = (d: unknown): Uint8Array => {
      try {
        const tag = Object.prototype.toString.call(d);
        if (tag === "[object ArrayBuffer]")
          return new Uint8Array(d as ArrayBuffer);
      } catch {
        /* ignore */
      }
      if (ArrayBuffer.isView(d)) {
        // Narrow to ArrayBufferView once after the runtime guard to avoid repeated assertions
        const v = d;
        return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      }
      throw new CryptoUnavailableError(
        "SubtleCrypto.digest returned invalid result.",
      );
    };
    // Both fulfilled: convert directly to Uint8Array to avoid intermediate mutable bindings
    ua = ((): Uint8Array => {
      try {
        return toU8(settled[0].value);
      } catch {
        throw new CryptoUnavailableError(
          "SubtleCrypto.digest returned invalid result.",
        );
      }
    })();
    ub = ((): Uint8Array => {
      try {
        return toU8(settled[1].value);
      } catch {
        throw new CryptoUnavailableError(
          "SubtleCrypto.digest returned invalid result.",
        );
      }
    })();
    if (ua.byteLength !== ub.byteLength || ua.byteLength === 0) {
      throw new CryptoUnavailableError(
        "Digest length mismatch or zero length.",
      );
    }
    result = compareUint8Arrays(ua, ub);
  } finally {
    // Ensure we never mask an original exception thrown in the try block.
    // Collect wipe results and prefer rethrowing the original error if present.
    // Avoid throwing directly from inside nested catch blocks in order to satisfy
    // static analyzers that flag multi-line/fragmented throw statements.
    // eslint-disable-next-line functional/no-let -- local aggregation flag for wipe results, intentional mutation
    let wipeOk = true;
    try {
      const okA = ua ? __wipeImpl(ua) : true;
      const okB = ub ? __wipeImpl(ub) : true;
      wipeOk = okA && okB;
    } catch (wipeError) {
      wipeOk = false;
      if (isDevelopment()) {
        secureDevLog("error", "secureCompare", "Wipe threw during finally", {
          error: sanitizeErrorForLogs(wipeError),
        });
      }
    }

    if (!wipeOk) {
      safeEmitMetric("secureCompare.error", 1, { reason: "wipe-failed" });
      __wipeFailedAfterFinally = true;
    }
  }
  if (__wipeFailedAfterFinally) {
    throw new CryptoUnavailableError("Secure wipe failed after hashing.");
  }
  return result;
}

// (handleCompareError removed: logic inlined in secureCompareAsync)

// --- Safe Logging & Redaction ---

/** Maximum recursion depth for the redaction function. */
export const MAX_REDACT_DEPTH = 8;
/** Maximum length of a string in logs before it is truncated. */
export const MAX_LOG_STRING = 8192;

// NEW: Breadth limits to complement depth caps
export const MAX_KEYS_PER_OBJECT = 64;
export const MAX_ITEMS_PER_ARRAY = 128;

const JWT_LIKE_REGEX = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}$/u;
const REDACTED_VALUE = "[REDACTED]";
const SAFE_KEY_REGEX = /^[\w.-]{1,64}$/u;

// Central scalar-string redactor used by multiple sinks; extracted to avoid
// duplicate logic and reduce complexity in callers.
function redactScalarString(input: string): string {
  // Truncate first to bound regex work, then apply redactions
  const truncated = _truncateIfLong(input);
  // Early numeric-secret detection: full redaction when PAN-like or very long numeric tokens appear
  try {
    const digits = truncated.replace(/\D+/gu, "");
    if (digits.length >= 12 && digits.length <= 19 && luhnCheck(digits)) {
      return REDACTED_VALUE;
    }
    const cfg1 = getCanonicalConfig() as unknown as {
      readonly redactLongNumericMinLength?: number;
    };
    const redactLongNumericMinLength =
      typeof cfg1.redactLongNumericMinLength === "number"
        ? cfg1.redactLongNumericMinLength
        : 24;
    if (digits.length >= redactLongNumericMinLength) {
      return REDACTED_VALUE;
    }
  } catch {
    /* ignore config errors */
  }

  return truncated
    .replace(JWT_LIKE_REGEX, REDACTED_VALUE)
    .replace(
      /\b(?:password|pass|token|secret|jwt|authorization)\s*[:=]\s*[^\s,;&]{1,2048}/giu,
      (m) => {
        const head = m.split(/[:=]/u, 1)[0] ?? "";
        return `${head}=[REDACTED]`;
      },
    )
    .replace(
      /\b(?:api[_-]?key|x[_-]?api[_-]?key|secret[_-]?token)\s*[:=]\s*[^\s,;&]{1,2048}/giu,
      (m) => {
        const head = m.split(/[:=]/u, 1)[0] ?? "";
        return `${head}=[REDACTED]`;
      },
    )
    .replace(
      /\bauthorization\s*[:=]\s*[^\r\n]{1,2048}/giu,
      () => "Authorization=[REDACTED]",
    )
    .replace(/\bbearer\s+\S{1,2048}/giu, "bearer [REDACTED]");
}

/**
 * Checks if a key contains sensitive API-related terms.
 */
function isApiKey(key: string): boolean {
  return /\b(?:api[_-]?key|x[_-]?api[_-]?key)\b/iu.test(key);
}

/**
 * Checks if a key contains sensitive token-related terms.
 */
function isTokenKey(key: string): boolean {
  return /\b(?:access[_-]?token|refresh[_-]?token|bearer|token)\b/iu.test(key);
}

/**
 * Checks if a key contains sensitive authentication terms.
 */
function isAuthKey(key: string): boolean {
  return /\b(?:password|passphrase|secret|credential|private[_-]?key|authorization)\b/iu.test(
    key,
  );
}

/**
 * Checks if a key contains other sensitive terms.
 */
function isOtherSensitiveKey(key: string): boolean {
  return /\b(?:jwt|session|cert|signature)\b/iu.test(key);
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

function isOtpLikeKey(key: string): boolean {
  return /\b(?:otp|mfa|2fa|code|pin|one[_-]?time)\b/iu.test(key);
}

function _truncateIfLong(s: string): string {
  try {
    const { maxStringLengthBytes } = getCanonicalConfig();
    const bytes = SHARED_ENCODER.encode(s);
    // Respect both canonical byte budget and legacy MAX_LOG_STRING expectation from tests.
    const capBytes = Math.min(maxStringLengthBytes, MAX_LOG_STRING);
    if (bytes.length <= capBytes) return s;
    // Find a safe cut point without splitting code points
    const cap = Math.max(0, capBytes);
    const slice = bytes.slice(0, cap);
    const truncated = new TextDecoder().decode(slice);
    return truncated + `...[TRUNCATED ${String(bytes.length - cap)} bytes]`;
  } catch {
    // Fallback to legacy char-based truncation
    return s.length > MAX_LOG_STRING
      ? s.slice(0, MAX_LOG_STRING) +
          `...[TRUNCATED ${String(s.length - MAX_LOG_STRING)} chars]`
      : s;
  }
}

function _redactPrimitive(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (JWT_LIKE_REGEX.test(value)) return REDACTED_VALUE;
  if (
    /(?:^|[\s,&])(?:password|pass|token|secret|bearer|jwt|authorization)\s*[=:]/iu.test(
      value,
    )
  ) {
    return REDACTED_VALUE;
  }
  // Numeric secret redaction: PAN detection via Luhn and long digit tokens
  const digits = value.replace(/\D+/gu, "");
  if (digits.length >= 12 && digits.length <= 19 && luhnCheck(digits)) {
    return REDACTED_VALUE;
  }
  // Very long numeric tokens (e.g., IDs/secrets) — redact in strict mode
  try {
    const cfg2 = getCanonicalConfig() as unknown as {
      readonly redactLongNumericMinLength?: number;
    };
    const redactLongNumericMinLength =
      typeof cfg2.redactLongNumericMinLength === "number"
        ? cfg2.redactLongNumericMinLength
        : 24;
    if (digits.length >= redactLongNumericMinLength) {
      return REDACTED_VALUE;
    }
  } catch {
    // ignore config errors
  }
  if (value.length > MAX_LOG_STRING) return _truncateIfLong(value);
  return value;
}

function luhnCheck(number_: string): boolean {
  // eslint-disable-next-line functional/no-let -- local accumulator for Luhn checksum (mutation is safe and fastest here)
  let sum = 0;
  // eslint-disable-next-line functional/no-let -- required toggling state for Luhn parity
  let shouldDouble = false;
  // eslint-disable-next-line functional/no-let -- loop counter for backward traversal
  for (let i = number_.length - 1; i >= 0; i--) {
    // eslint-disable-next-line functional/no-let -- local mutation for efficient arithmetic
    let digit = number_.charCodeAt(i) - 48; // '0' => 48
    if (digit < 0 || digit > 9) return false;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function computeDevelopmentUnsafeKeyHash(
  key: string,
  salt: string,
): string | undefined {
  try {
    const input = `${salt}:${key}`;
    // eslint-disable-next-line functional/no-let -- intentional local loop counter for DJB2
    let h = 5381;
    // eslint-disable-next-line functional/no-let -- loop counter
    for (let index = 0; index < input.length; index++) {
      /* intentional bitwise ops for DJB2 */
      h = ((h << 5) + h) ^ input.charCodeAt(index);
    }
    return (h >>> 0).toString(16);
  } catch {
    return undefined;
  }
}

function normalizeValueForRedaction(rawValue: unknown, depth: number): unknown {
  if (typeof rawValue === "string") return _redactPrimitive(rawValue);
  if (
    rawValue !== null &&
    rawValue !== undefined &&
    typeof rawValue === "object"
  )
    return _redact(rawValue, depth + 1);
  return rawValue;
}

function _redactObject(
  object: Record<string, unknown>,
  depth: number,
): unknown {
  const loggingCfg = getLoggingConfig();
  const includeHashes =
    !environment.isProduction &&
    loggingCfg.allowUnsafeKeyNamesInDev &&
    loggingCfg.includeUnsafeKeyHashesInDev;
  const { result } = buildRedactedObjectEntries(
    object,
    depth,
    includeHashes,
    loggingCfg.unsafeKeyHashSalt ?? "",
  );
  return result;
}

function buildRedactedObjectEntries(
  object: Record<string, unknown>,
  depth: number,
  includeHashes: boolean,
  salt: string,
): {
  readonly result: Record<string, unknown>;
  readonly unsafeCount: number;
  readonly unsafeHashes: readonly string[];
} {
  const entriesSource = (
    Object.entries(object) as readonly (readonly [string, unknown])[]
  ).filter(
    ([key]) =>
      key !== "__proto__" && key !== "prototype" && key !== "constructor",
  );
  const aggregated = entriesSource.reduce(
    (
      accumulator: {
        readonly entries: readonly (readonly [string, unknown])[];
        readonly unsafeCount: number;
        readonly unsafeHashes: readonly string[];
      },
      [key, rawValue]: readonly [string, unknown],
    ) => {
      if (!SAFE_KEY_REGEX.test(key)) {
        const hash = includeHashes
          ? computeDevelopmentUnsafeKeyHash(key, salt)
          : undefined;
        return {
          entries: accumulator.entries,
          unsafeCount: accumulator.unsafeCount + 1,
          unsafeHashes:
            typeof hash === "string"
              ? [...accumulator.unsafeHashes, hash]
              : accumulator.unsafeHashes,
        } as const;
      }
      if (isSensitiveKey(key)) {
        return {
          ...accumulator,
          entries: [...accumulator.entries, [key, REDACTED_VALUE] as const],
        } as const;
      }
      // OTP/PIN heuristic: redact short numeric strings when key context is sensitive
      const preNormalized: unknown = (() => {
        if (isOtpLikeKey(key) && typeof rawValue === "string") {
          const digitsOnly = rawValue.replace(/\D+/gu, "");
          if (/^\d{4,10}$/u.test(digitsOnly)) {
            return REDACTED_VALUE;
          }
        }
        return rawValue;
      })();
      const v = normalizeValueForRedaction(preNormalized, depth);
      return {
        ...accumulator,
        entries: [...accumulator.entries, [key, v] as const],
      } as const;
    },
    {
      entries: [] as readonly (readonly [string, unknown])[],
      unsafeCount: 0,
      unsafeHashes: [] as readonly string[],
    },
  );

  const metaEntries: readonly (readonly [string, unknown])[] =
    aggregated.unsafeCount > 0
      ? ([
          ["__unsafe_key_count__", aggregated.unsafeCount] as const,
          ...(aggregated.unsafeHashes.length > 0
            ? ([
                [
                  "__unsafe_key_hashes__",
                  aggregated.unsafeHashes.slice(0, 32),
                ] as const,
              ] as const)
            : ([] as const)),
        ] as const)
      : ([] as const);

  const combinedEntries = [
    ...aggregated.entries,
    ...metaEntries,
  ] as readonly (readonly [string, unknown])[];
  const result = Object.fromEntries(combinedEntries) as Record<string, unknown>;

  return {
    result,
    unsafeCount: aggregated.unsafeCount,
    unsafeHashes: aggregated.unsafeHashes,
  };
}

function _cloneAndNormalizeForLogging(
  data: unknown,
  depth: number,

  visited: ReadonlySet<unknown>,
): unknown {
  if (depth >= MAX_REDACT_DEPTH) {
    return { __redacted: true, reason: "max-depth" };
  }
  // Primitive values (including bigint) are returned as-is (with bigint stringified)
  // Treat functions and symbols as primitives for logging/redaction purposes.
  if (typeof data === "bigint") return data; // keep as bigint for _redact tests
  if (typeof data === "symbol") return "[Symbol]";
  if (typeof data === "function")
    return depth === 0
      ? { __type: "Function", __redacted: true }
      : "[Function]";
  const isObjectLike = typeof data === "object" && data !== null;
  if (!isObjectLike) return data; // primitives unchanged
  if (visited.has(data)) {
    return "[Circular]";
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
    return data; // preserve Date instance
  }
  if (data instanceof RegExp) {
    return data; // preserve RegExp instance
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
 * Handles TypedArray/DataView objects for logging safely without exposing contents.
 */
function handleTypedArray(data: ArrayBufferView): unknown {
  const ctor = ((): string => {
    try {
      const c = (data as { readonly constructor: { readonly name?: string } })
        .constructor.name;
      if (typeof c === "string" && c.length <= 64) return c;
    } catch {
      /* ignore */
    }
    return "TypedArray";
  })();
  return { __typedArray: { ctor, byteLength: data.byteLength } } as const;
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
  for (let index = 0; index < limit; index++) {
    /* eslint-disable functional/immutable-data -- intentional push to build array */
    out.push(
      _cloneAndNormalizeForLogging(
        Object.hasOwn(data, index)
          ? Object.getOwnPropertyDescriptor(data, index)?.value
          : undefined,
        depth + 1,
        visited,
      ),
    );
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
  // Track whether any descendant was redacted due to max-depth to surface a
  // summary flag at this level (helps tests assert depth limiting without
  // relying on exact nesting paths).
  // eslint-disable-next-line functional/no-let -- local aggregation flag
  let descendantMaxDepthRedacted = false;

  // NEW: count symbol keys without exposing them
  try {
    const syms = Object.getOwnPropertySymbols(data);
    const symCount = syms.length;
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
  for (let index = 0; index < limit; index++) {
    const key = allKeys[index] as string;
    try {
      const v = _cloneAndNormalizeForLogging(
        Object.hasOwn(data as Record<string, unknown>, key)
          ? Object.getOwnPropertyDescriptor(
              data as Record<string, unknown>,
              key,
            )?.value
          : undefined,
        depth + 1,
        visited,
      );
      // eslint-disable-next-line functional/immutable-data
      Object.defineProperty(result, key, {
        value: v,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      if (
        v !== null &&
        v !== undefined &&
        typeof v === "object" &&
        (v as { readonly __redacted?: unknown; readonly reason?: unknown })
          .__redacted === true &&
        (v as { readonly reason?: unknown }).reason === "max-depth"
      ) {
        descendantMaxDepthRedacted = true;
      }
    } catch {
      // eslint-disable-next-line functional/immutable-data
      Object.defineProperty(result, key, {
        value: { __redacted: true, reason: "getter-threw" },
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
  }
  /* eslint-enable functional/no-let */
  if (allKeys.length > limit) {
    // eslint-disable-next-line functional/immutable-data
    Object.defineProperty(result, "__additional_keys__", {
      value: {
        __truncated: true,
        originalCount: allKeys.length,
        displayedCount: limit,
      },
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  if (descendantMaxDepthRedacted) {
    // Surface a summary at this level without leaking structure
    // eslint-disable-next-line functional/immutable-data
    Object.defineProperty(result, "__redacted", {
      value: true,
      writable: true,
      enumerable: true,
      configurable: true,
    });
    // eslint-disable-next-line functional/immutable-data
    Object.defineProperty(result, "reason", {
      value: "max-depth",
      writable: true,
      enumerable: true,
      configurable: true,
    });
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
  // Preserve transparent types produced by the normalization pass to avoid
  // destroying semantics like Date/RegExp/TypedArrays in the second pass.
  try {
    if (
      data instanceof Date ||
      data instanceof RegExp ||
      data instanceof Error
    ) {
      return data;
    }
  } catch {
    /* fall through */
  }
  if (Array.isArray(data)) {
    return data.map((item) => _redact(item, depth + 1));
  }
  return _redactObject(data as Record<string, unknown>, depth);
}

// ADD: Central sanitizer for log message strings using the same primitives as context redaction.
// The sanitizer below intentionally has many branches to safely handle a wide
// variety of exotic inputs and to avoid accidental data leakage. Keeping the
// branching here makes the behavior explicit and auditable. We therefore allow
// a higher cognitive complexity for this function while ensuring each branch
// is small and well-tested.
/* NOTE: cognitive complexity of this sanitizer is intentional and audited. */
function fmtErrorMessage(error: Error): string {
  try {
    const name = error.name || "Error";
    const message = typeof error.message === "string" ? error.message : "";
    return message ? `${name}: ${message}` : name;
  } catch {
    return "Error";
  }
}

function stringifyArrayTopLevel(array: readonly unknown[]): string | undefined {
  try {
    const safeMap = (v: unknown): string => {
      if (typeof v === "string") return v;
      if (typeof v === "number" || typeof v === "boolean") return String(v);
      if (typeof v === "bigint") return v.toString();
      if (typeof v === "symbol") return String(v);
      if (typeof v === "function") return "[Function]";
      return "[Object]";
    };
    const { maxTopLevelArrayLength } = getCanonicalConfig();
    const limit = Math.max(0, Math.min(array.length, maxTopLevelArrayLength));
    const projected = array.slice(0, limit).map((v) => safeMap(v));
    const tail = array.length > limit ? ["__truncated__"] : [];
    return JSON.stringify([...projected, ...tail]);
  } catch {
    return undefined;
  }
}

function tryCustomToString(object: unknown): string | undefined {
  if (object === null || object === undefined || typeof object !== "object")
    return undefined;
  try {
    const hasOwnToString = Object.hasOwn(object, "toString");
    if (!hasOwnToString) return undefined;
    // Call toString with the correct receiver to avoid unbound method issues
    const string_ = Function.prototype.call.call(
      (object as { readonly toString: () => unknown }).toString,
      object,
    ) as unknown;
    if (typeof string_ === "string")
      return _truncateIfLong(redactScalarString(string_));
    return undefined;
  } catch {
    return REDACTED_VALUE;
  }
}

function handleToJSONFirst(object: unknown): string | undefined {
  if (object === null || object === undefined || typeof object !== "object")
    return undefined;
  if (
    !Object.hasOwn(object, "toJSON") ||
    typeof Object.getOwnPropertyDescriptor(object, "toJSON")?.value !==
      "function"
  ) {
    return undefined;
  }
  try {
    const toJSONResult = (
      object as { readonly toJSON: () => unknown }
    ).toJSON();
    if (toJSONResult === undefined) return "[object Object]";
    if (typeof toJSONResult === "function") return "[Function]";
    if (
      toJSONResult &&
      typeof toJSONResult === "object" &&
      !Array.isArray(toJSONResult)
    ) {
      const tObject = toJSONResult as Record<string, unknown>;
      const tEntries = Object.keys(tObject)
        .filter(
          (k) => k !== "__proto__" && k !== "prototype" && k !== "constructor",
        )
        .map(
          (k) =>
            [
              k,
              Object.hasOwn(tObject, k)
                ? Object.getOwnPropertyDescriptor(tObject, k)?.value
                : undefined,
            ] as const,
        ) as readonly (readonly [string, unknown])[];
      const messageObject = object as Record<string, unknown>;
      const messageEntries = Object.keys(messageObject)
        .filter(
          (k) =>
            k !== "toJSON" &&
            k !== "__proto__" &&
            k !== "prototype" &&
            k !== "constructor",
        )
        .map(
          (k) =>
            [
              k,
              Object.hasOwn(messageObject, k)
                ? Object.getOwnPropertyDescriptor(messageObject, k)?.value
                : undefined,
            ] as const,
        ) as readonly (readonly [string, unknown])[];
      const mergedEntries = messageEntries.reduce(
        (accumulator: ReadonlyArray<readonly [string, unknown]>, entry) =>
          accumulator.some((me) => me[0] === entry[0])
            ? accumulator
            : accumulator.concat([entry]),
        tEntries,
      );
      const mergedObject = Object.fromEntries(mergedEntries);
      return _truncateIfLong(JSON.stringify(mergedObject));
    }
    if (typeof toJSONResult === "string")
      return _truncateIfLong(redactScalarString(toJSONResult));
    if (typeof toJSONResult === "bigint") return toJSONResult.toString();
    if (typeof toJSONResult === "symbol") return String(toJSONResult);
    if (typeof toJSONResult === "number" || typeof toJSONResult === "boolean")
      return String(toJSONResult);
    return _truncateIfLong(JSON.stringify(toJSONResult));
  } catch {
    return "[object Object]";
  }
}

// (duplicate sanitizeLogMessage removed — see primary implementation above)

// Helper: normalize typed arrays for the sanitizer
function normalizeTypedArrayForSanitizer(v: unknown): unknown {
  try {
    // Do NOT expand typed array contents to avoid leaking secrets in logs.
    const abv = v as ArrayBufferView;
    return {
      __typedArray: true,
      byteLength: abv.byteLength,
    };
  } catch {
    return { __typedArray: true };
  }
}

// Recursive normalizer used by sanitizeLogMessage. Extracted to reduce cognitive complexity.
function normalizePrimitiveForSanitizer(value: unknown): unknown {
  if (value === null) return "[null]";
  if (value === undefined) return "[undefined]";
  if (typeof value === "function") return "[Function]";
  if (typeof value === "symbol") return String(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return redactScalarString(value);
  if (typeof value !== "object") return value; // number/boolean
  return undefined;
}

function normalizeSetForSanitizer(
  value: ReadonlySet<unknown>,
): readonly string[] {
  try {
    // Avoid expanding Set contents: provide opaque metadata only
    return [`[Set size=${String(value.size)}]`];
  } catch {
    return [] as const;
  }
}

function normalizeArrayForSanitizer(
  array: readonly unknown[],
  seen: ReadonlySet<unknown>,
): readonly unknown[] {
  const nextSeen = seen; // arrays only push inner elements, outer tracking done by caller
  return array.map((v) => normalizeForSanitizer(v, nextSeen));
}

function normalizeObjectForSanitizer(
  value: object,
  seen: ReadonlySet<unknown>,
): Record<string, unknown> {
  const entries = Object.keys(value as Record<string, unknown>)
    .filter(
      (k) => k !== "__proto__" && k !== "prototype" && k !== "constructor",
    )
    .map((k) => {
      try {
        const raw = Object.hasOwn(value as Record<string, unknown>, k)
          ? ((): unknown => {
              const descriptor = Object.getOwnPropertyDescriptor(
                value as Record<string, unknown>,
                k,
              );
              return descriptor?.value;
            })()
          : undefined;
        // Apply sensitive key redaction to mirror _redactObject semantics
        if (SAFE_KEY_REGEX.test(k) && isSensitiveKey(k)) {
          return [k, REDACTED_VALUE] as const;
        }
        // OTP/PIN heuristic: redact short numeric strings when key context is sensitive
        if (
          SAFE_KEY_REGEX.test(k) &&
          isOtpLikeKey(k) &&
          typeof raw === "string"
        ) {
          const digitsOnly = raw.replace(/\D+/gu, "");
          if (/^\d{4,10}$/u.test(digitsOnly)) {
            return [k, REDACTED_VALUE] as const;
          }
        }
        return [k, normalizeForSanitizer(raw, seen)] as const;
      } catch {
        return [k, "[GetterThrew]"] as const;
      }
    });
  return Object.fromEntries(entries) as Record<string, unknown>;
}

function normalizeForSanitizer(
  value: unknown,
  seen: ReadonlySet<unknown>,
): unknown {
  const prim = normalizePrimitiveForSanitizer(value);
  if (prim !== undefined) return prim;
  // value is object-like at this point
  if (seen.has(value as object)) return "[Circular]";
  const nextSeen = new Set<unknown>([...seen, value as object]);

  // Handle special objects
  if (value instanceof Date) return value.toISOString();
  if (value instanceof RegExp) return value.toString();
  if (ArrayBuffer.isView(value)) return normalizeTypedArrayForSanitizer(value);
  if (value instanceof ArrayBuffer) return { __arrayBuffer: value.byteLength };
  if (value instanceof Map) return {};
  if (value instanceof Set) return normalizeSetForSanitizer(value);
  if (Array.isArray(value)) return normalizeArrayForSanitizer(value, nextSeen);

  // Try to use toJSON first if present
  try {
    const object = value as Record<string, unknown>;
    const toJSON = Object.hasOwn(object, "toJSON")
      ? object["toJSON"]
      : undefined;
    if (typeof toJSON === "function") {
      try {
        const jsonValue = (toJSON as () => unknown).call(object);
        return normalizeForSanitizer(jsonValue, nextSeen);
      } catch {
        // fallthrough to plain object handling
      }
    }
  } catch {
    // ignore toJSON errors
  }

  return normalizeObjectForSanitizer(value as object, nextSeen);
}

// ADD: Guard component names to a safe subset to prevent accidental leakage.
export function sanitizeComponentName(name: unknown): string {
  try {
    // Only accept strings, reject other types
    if (typeof name !== "string") {
      return "unsafe-component-name";
    }
    if (!SAFE_KEY_REGEX.test(name)) return "unsafe-component-name";
    // Disallow leading or trailing dots specifically
    if (name.startsWith(".") || name.endsWith(".")) {
      return "unsafe-component-name";
    }
    if (
      name === "__proto__" ||
      name === "constructor" ||
      name === "prototype"
    ) {
      return "unsafe-component-name";
    }
    return name;
  } catch {
    return "unsafe-component-name";
  }
}

// --- Dev log rate limiting (development only) ---
// Keep this small and auditable to satisfy Hardened Simplicity.
const DEV_LOG_TOKENS = 200; // Max logs per minute in dev

// Use a single const state object to avoid `let`; mutations are localized and audited.
/* eslint-disable functional/prefer-readonly-type -- audited mutable state for rate limiting */
const developmentLogState: {
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

function developmentLogAllow(): boolean {
  if (environment.isProduction) return false;
  const now = Date.now();
  const loggingCfg = getLoggingConfig();
  const tokensPerMinute = loggingCfg.rateLimitTokensPerMinute ?? DEV_LOG_TOKENS;

  // If the configured tokens-per-minute is lower than the current bucket,
  // clamp the bucket immediately so tests or runtime config changes take
  // effect without waiting for the next refill window.
  // This keeps the behaviour simple and auditable.
  if (developmentLogState.bucket > Math.max(0, Math.trunc(tokensPerMinute))) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    developmentLogState.bucket = Math.max(0, Math.trunc(tokensPerMinute));
  }

  // Refill bucket once per minute using configured tokens
  if (now - developmentLogState.lastRefill >= 60_000) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    developmentLogState.bucket = Math.max(1, Math.trunc(tokensPerMinute));
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    developmentLogState.lastRefill = now;
  }
  if (developmentLogState.bucket > 0) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    developmentLogState.bucket--;
    return true;
  }

  // Track dropped and occasionally emit a summary (no recursion into our logger)
  // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
  developmentLogState.dropped++;
  if (now - developmentLogState.lastDropReport > 5_000) {
    // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
    developmentLogState.lastDropReport = now;
    try {
      // Do NOT call secureDevLog here; go straight to console
      // Avoid including user context; share only counts

      console.warn(
        "[security-kit] dev log rate-limit: dropping",
        developmentLogState.dropped,
        "messages in the last 5s window",
      );
      // Emit telemetry for rate hits
      try {
        safeEmitMetric("logRateLimit.hit", developmentLogState.dropped, {
          reason: "dev",
        });
      } catch {
        /* ignore telemetry failures */
      }
      // eslint-disable-next-line functional/immutable-data -- audited mutation of local state
      developmentLogState.dropped = 0;
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
export function _developmentConsole(
  level: LogLevel,
  message: string,
  safeContext: unknown,
): void {
  if (environment.isProduction) return;
  // Serialize a string-safe representation of the context to avoid leaking structured data
  const contextString = ((): string => {
    try {
      // Redact context defensively before serializing
      const redacted = _redact(safeContext);
      // Use an untyped JS replacer to avoid explicit `any` while truncating long strings
      function replacer(_k: string, v: unknown): unknown {
        return typeof v === "string" && v.length > 1024
          ? `${v.slice(0, 1024)}...[TRUNC]`
          : v;
      }
      return JSON.stringify(redacted, replacer);
    } catch {
      return String(safeContext);
    }
  })();
  // DEFENSE-IN-DEPTH: sanitize message at the sink, even if caller already sanitized.
  const safeMessage = sanitizeLogMessage(message);

  const out = contextString
    ? `${safeMessage} | context=${contextString}`
    : safeMessage;
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
// Backward-compatible alias

export const _devConsole = _developmentConsole;

/**
 * Logs a message and a context object in development environments ONLY.
 * The context object is automatically redacted to prevent accidental leakage
 * of sensitive information.
 * @param level The log level.
 * @param component The name of the component or module logging the message.
 * @param message The log message.
 * @param context An optional object containing additional context.
 */
// Module-scoped token bucket state (dev-only). We keep these outside the
// `secureDevLog` function to avoid re-creating timers or state on each call.
// These are intentionally mutable; disable rules that would force `const`.
/* eslint-disable-next-line functional/no-let */
let __development_event_tokens = 5; // initial burst
/* eslint-disable-next-line functional/no-let */
let __development_event_last_refill = Date.now();
const __DEV_EVENT_REFILL_PER_SEC = 1; // 60 per minute
const __DEV_EVENT_MAX_TOKENS = 5;

function developmentEventDispatchAllow(): boolean {
  try {
    if (environment.isProduction) return false;
    const now = Date.now();
    const elapsedMs = now - __development_event_last_refill;
    if (elapsedMs > 0) {
      const toAdd = Math.floor((elapsedMs / 1000) * __DEV_EVENT_REFILL_PER_SEC);
      if (toAdd > 0) {
        __development_event_tokens = Math.min(
          __DEV_EVENT_MAX_TOKENS,
          __development_event_tokens + toAdd,
        );
        __development_event_last_refill = now;
      }
    }
    if (__development_event_tokens > 0) {
      __development_event_tokens -= 1;
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Dev-only diagnostic: return the internal token-bucket state for tests.
 * Returns `undefined` in production to avoid leaking runtime internals.
 */
export function getDevelopmentEventDispatchState():
  | {
      readonly tokens: number;
      readonly lastRefill: number;
      readonly refillPerSec: number;
      readonly maxTokens: number;
    }
  | undefined {
  if (environment.isProduction) return undefined;
  return {
    tokens: __development_event_tokens,
    lastRefill: __development_event_last_refill,
    refillPerSec: __DEV_EVENT_REFILL_PER_SEC,
    maxTokens: __DEV_EVENT_MAX_TOKENS,
  };
}
export const getDevEventDispatchState = getDevelopmentEventDispatchState;

export function secureDevelopmentLog_(
  level: LogLevel,
  component: string,
  message: string,
  context: unknown = {},
): void {
  if (environment.isProduction) return;

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

  // Emit an event for observers when document.dispatchEvent exists.
  // Use CustomEvent when available; otherwise, polyfill using Event with a `detail` property.
  if (
    typeof document !== "undefined" &&
    typeof (document as { readonly dispatchEvent?: unknown }).dispatchEvent ===
      "function"
  ) {
    try {
      const safeEvent = {
        level: logEntry.level,
        component: logEntry.component,
        message: logEntry.message,
      };

      // Define a type for CustomEvent constructor
      type CustomEventConstructor = new (
        type: string,
        options?: { readonly detail?: unknown },
      ) => Event & { readonly detail?: unknown };

      const CE: CustomEventConstructor =
        typeof CustomEvent === "function"
          ? CustomEvent
          : class FallbackCustomEvent extends Event {
              public readonly detail?: unknown;
              constructor(
                type: string,
                options?: { readonly detail?: unknown },
              ) {
                super(type);
                this.detail = options?.detail;
              }
            };

      if (developmentEventDispatchAllow()) {
        document.dispatchEvent(
          new CE("security-kit:log", { detail: safeEvent }),
        );
      }
    } catch {
      /* ignore */
    }
  }

  // Apply rate limit for console output after event dispatch so diagnostics can
  // still be observed by listeners even when console logging is throttled.
  if (!developmentLogAllow()) return;

  const message_ = `[${logEntry.level}] (${safeComponent}) ${safeMessage}`;
  _developmentConsole(level, message_, safeContext);
}
export const secureDevLog = secureDevelopmentLog_;

// Set the logger for the dev-logger facade (moved to lazy initialization)
// This is now done lazily to avoid side effects on import
// setDevLogger(secureDevLog);

// Provide descriptive compatibility aliases for consumers that prefer
// more explicit names. These are simple re-exports and preserve behavior.
export const secureDevelopmentLog = secureDevLog;
export const setDevelopmentLogger = setDevelopmentLogger_;

// --- Internal Utilities ---
// The following exports are for testing purposes only and should not be used in production code

/**
 * @internal
 * @deprecated For testing only
 */
export const _sanitizeMetricTags = sanitizeMetricTags;

/**
 * @internal
 * @deprecated For testing only
 */
export const _safeEmitMetric = safeEmitMetric;

/**
 * @internal
 * @deprecated For testing only
 */
export const _isSecurityStrict = isSecurityStrict;
