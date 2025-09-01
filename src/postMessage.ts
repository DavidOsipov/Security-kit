// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Hardened utilities for secure cross-context communication using `postMessage`.
 * - Enforces strict origin validation
 * - Converts incoming payloads to null-prototype objects to prevent prototype pollution
 * - Optional schema or function validators (required in production)
 * - Safe diagnostic/fingerprinting behavior with crypto checks
 *
 * Important runtime behavior changes (compared to earlier draft):
 * - No top-level `await`. Use synchronous environment checks at creation time.
 * - Production requires crypto availability for diagnostics; creation will fail fast
 *   if `crypto.getRandomValues` is not present.
 * - `expectedSource` may be a comparator function for robust cross-context matching.
 *
 * This file contains a few carefully-scoped `eslint-disable` comments to allow
 * low-level, audited mutations (null-proto creation, controlled caches).
 */

/* eslint-disable functional/no-let, functional/immutable-data */

import {
  InvalidParameterError,
  InvalidConfigurationError,
  CryptoUnavailableError,
  TransferableNotAllowedError,
  EncodingError,
  sanitizeErrorForLogs,
} from "./errors";
import { ensureCrypto } from "./state";
import { secureDevLog as secureDevelopmentLog } from "./utils";
import { arrayBufferToBase64 } from "./encoding-utils";
import { SHARED_ENCODER } from "./encoding";
import { isForbiddenKey } from "./constants";
import { environment } from "./environment";
import { normalizeOrigin as normalizeUrlOrigin } from "./url";

// --- Interfaces and Types ---

export interface SecurePostMessageOptions {
  readonly targetWindow: Window;
  readonly payload: unknown;
  readonly targetOrigin: string;
  readonly wireFormat?: "json" | "structured" | "auto";
  readonly sanitize?: boolean; // default true
  readonly allowTransferables?: boolean; // default false
  readonly allowTypedArrays?: boolean; // default false
}

export interface SecurePostMessageListener {
  readonly destroy: () => void;
}

export type SchemaValue = "string" | "number" | "boolean" | "object" | "array";

export type MessageListenerContext = {
  readonly origin: string;
  readonly source?: unknown;
  readonly ports?: readonly MessagePort[] | undefined;
  readonly event?: MessageEvent;
};

export type CreateSecurePostMessageListenerOptions = {
  readonly allowedOrigins: readonly string[];
  readonly onMessage: (data: unknown, context?: MessageListenerContext) => void;
  readonly validate?: ((d: unknown) => boolean) | Record<string, SchemaValue>;
  // New hardening options
  readonly allowOpaqueOrigin?: boolean; // default false
  readonly expectedSource?: Window | MessagePort | ((s: unknown) => boolean); // optional stronger binding, now accepts comparator
  readonly allowExtraProps?: boolean; // default false when using schema
  readonly enableDiagnostics?: boolean; // default false; gates fingerprints in prod
  // freezePayload: when true (default), the sanitized payload will be deeply frozen
  // before being passed to the consumer. When false, callers accept responsibility
  // for not mutating the payload.
  readonly freezePayload?: boolean;
  readonly wireFormat?: "json" | "structured" | "auto"; // default json
  readonly deepFreezeNodeBudget?: number;
  readonly allowTransferables?: boolean; // default false: disallow transferables like MessagePort/ArrayBuffer
  readonly allowTypedArrays?: boolean; // default false: disallow TypedArray/DataView/ArrayBuffer without opt-in
};
export { validateTransferables };

// --- Constants ---

export const POSTMESSAGE_MAX_PAYLOAD_BYTES = 32 * 1024;
export const POSTMESSAGE_MAX_PAYLOAD_DEPTH = 8;

// Small default limits for diagnostics to prevent DoS via expensive hashing
const DEFAULT_DIAGNOSTIC_BUDGET = 5; // fingerprints per minute

// Budget for deep-freeze traversal to avoid CPU/DoS via very wide objects
const DEFAULT_DEEP_FREEZE_NODE_BUDGET = 5000; // tunable

// --- Utilities ---

/**
 * Safe "now" helper that works in browser & node-like hosts.
 */
function now(): number {
  return typeof performance !== "undefined" &&
    typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

/**
 * Synchronous check for presence of a secure RNG in the environment.
 * This intentionally does not await `ensureCrypto()` because some environments
 * require an async initialization; we need a fast, non-async gate for
 * production fail-fast behavior.
 */
function syncCryptoAvailable(): boolean {
  try {
    // globalThis.crypto.getRandomValues presence is the minimal sync capability.
    // In Node 20+, globalThis.crypto is present. In browsers, it is present.
    // This is a conservative check; ensureCrypto() may still be used for
    // full async work (e.g., subtle).
    const g = globalThis as unknown as { readonly crypto?: unknown };
    if (!g || typeof g.crypto === "undefined") return false;
    const c = g.crypto as unknown as { readonly getRandomValues?: unknown };
    return !!(c && typeof c.getRandomValues === "function");
  } catch {
    return false;
  }
}

// Centralized crypto availability checker with consistent error handling and logging
function checkCryptoAvailabilityForSecurityFeature(
  featureName: string,
  requireInProduction = true,
): void {
  if (!syncCryptoAvailable()) {
    if (requireInProduction && environment.isProduction) {
      // Production requires crypto for security guarantees
      try {
        _diagnosticsDisabledDueToNoCryptoInProduction = true;
        secureDevelopmentLog(
          "error",
          "postMessage",
          `Secure crypto unavailable in production for ${featureName}`,
          {},
        );
      } catch {
        /* best-effort logging */
      }
      throw new CryptoUnavailableError(
        `Secure crypto required in production for ${featureName}`,
      );
    } else if (environment.isProduction) {
      // Non-critical crypto usage in production - disable diagnostics
      try {
        _diagnosticsDisabledDueToNoCryptoInProduction = true;
        secureDevelopmentLog(
          "warn",
          "postMessage",
          `Secure crypto unavailable in production; ${featureName} disabled`,
          {},
        );
      } catch {
        /* best-effort logging */
      }
    }
  }
}

// Helper: call consumer and centralize async rejection/sync throw handling so
// the main `handler` function stays small and easier to lint/verify.
function invokeConsumerSafely(
  consumer: (d: unknown, c?: MessageListenerContext) => void,
  data: unknown,
  contextOrOrigin: string | MessageListenerContext,
): void {
  // Normalize origin for logging regardless of whether a raw origin string
  // or the richer MessageListenerContext was provided.
  const originForLogs =
    typeof contextOrOrigin === "string"
      ? contextOrOrigin
      : contextOrOrigin?.origin;

  try {
    const result = consumer(
      data,
      typeof contextOrOrigin === "string" ? undefined : contextOrOrigin,
    );
    Promise.resolve(result).catch((asyncError) => {
      try {
        secureDevelopmentLog("error", "postMessage", "Listener handler error", {
          origin: originForLogs,
          error: sanitizeErrorForLogs(asyncError),
        });
      } catch {
        /* best-effort logging */
      }
    });
  } catch (error: unknown) {
    try {
      secureDevelopmentLog("error", "postMessage", "Listener handler error", {
        origin: originForLogs,
        error: sanitizeErrorForLogs(error),
      });
    } catch {
      /* best-effort logging */
    }
  }
}

function isArrayBufferViewSafe(value: unknown): value is ArrayBufferView {
  try {
    return (
      typeof ArrayBuffer !== "undefined" &&
      typeof ArrayBuffer.isView === "function" &&
      ArrayBuffer.isView(value as ArrayBufferView)
    );
  } catch {
    return false;
  }
}

/**
 * Safely gets the constructor name of an object, handling cross-realm scenarios.
 * @param value The value to get the constructor name for.
 * @returns The constructor name as a string, or undefined if it cannot be determined.
 */
function safeCtorName(value: unknown): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  try {
    const proto = Object.getPrototypeOf(value);
    if (!proto) return undefined;
    const protoWithConstructor = proto as Record<string, unknown>;
    const constructor = protoWithConstructor.constructor;
    if (!constructor || typeof constructor !== "function") {
      return undefined;
    }
    const ctor = constructor as Function;
    const namePropertyValue = (ctor as { readonly name?: unknown }).name;
    const nameProperty =
      typeof namePropertyValue === "string" ? namePropertyValue : undefined;
    const maybeName =
      typeof nameProperty === "string" ? nameProperty : undefined;
    return typeof maybeName === "string" ? maybeName : undefined;
  } catch {
    return undefined;
  }
}

// --- Internal Security Helpers ---

/**
 * Validates that payload does not contain disallowed transferable objects
 * like MessagePort, ArrayBuffer, or SharedArrayBuffer unless explicitly allowed.
 */
/* eslint-disable-next-line sonarjs/cognitive-complexity -- Single-pass defensive validation requires conditional branches; splitting would harm auditability without real risk reduction. */
function validateTransferables(
  payload: unknown,
  allowTransferables: boolean,
  allowTypedArrays: boolean,
  depth = 0,
  maxDepth = POSTMESSAGE_MAX_PAYLOAD_DEPTH,
  visited?: WeakSet<object>,
): void {
  if (depth > maxDepth) return; // depth check handled elsewhere
  if (payload === null || typeof payload !== "object") return;

  // Handle circular references
  visited ??= new WeakSet<object>();
  if (visited.has(payload as object)) return;

  visited.add(payload as object);

  // Check for disallowed transferable types
  const ctorName = safeCtorName(payload);

  // MessagePort and other transferable objects
  if (
    ctorName === "MessagePort" ||
    ctorName === "ReadableStream" ||
    ctorName === "WritableStream" ||
    ctorName === "TransformStream"
  ) {
    if (!allowTransferables) {
      throw new TransferableNotAllowedError(
        `Transferable object ${ctorName} is not allowed unless allowTransferables=true`,
      );
    }
  }

  // ArrayBuffer and typed arrays
  if (ctorName === "ArrayBuffer" || ctorName === "SharedArrayBuffer") {
    if (!allowTypedArrays) {
      throw new TransferableNotAllowedError(
        `${ctorName} is not allowed unless allowTypedArrays=true`,
      );
    }
  }

  // TypedArray and DataView check
  try {
    if (isArrayBufferViewSafe(payload)) {
      if (!allowTypedArrays) {
        throw new TransferableNotAllowedError(
          "TypedArray/DataView is not allowed unless allowTypedArrays=true",
        );
      }
    }
  } catch {
    // If ArrayBuffer.isView throws, continue
  }

  // Recursively check nested objects and arrays
  if (Array.isArray(payload)) {
    for (const item of payload) {
      validateTransferables(
        item,
        allowTransferables,
        allowTypedArrays,
        depth + 1,
        maxDepth,
        visited,
      );
    }
    return;
  }

  for (const key of Object.keys(payload as Record<string, unknown>)) {
    try {
      const desc = Object.getOwnPropertyDescriptor(
        payload as Record<string, unknown>,
        key,
      );
      if (desc && Object.hasOwn(desc, "value")) {
        const descValue = desc.value as unknown;
        validateTransferables(
          descValue,
          allowTransferables,
          allowTypedArrays,
          depth + 1,
          maxDepth,
          visited,
        );
      }
    } catch {
      continue;
    }
  }
}

/**
 * Converts objects to null-prototype objects to prevent prototype pollution attacks.
 * Also enforces depth limits and strips forbidden keys.
 */
/* eslint-disable-next-line sonarjs/cognitive-complexity -- Defensive conversions and filtering require explicit branches to stay auditable. */
function toNullProto(
  object: unknown,
  depth = 0,
  maxDepth = POSTMESSAGE_MAX_PAYLOAD_DEPTH,
  visited?: WeakSet<object>,
): unknown {
  if (depth > maxDepth) {
    throw new InvalidParameterError(
      `Payload depth exceeds limit of ${maxDepth}`,
    );
  }

  if (object === null || typeof object !== "object") {
    return object;
  }

  // Host-type rejection: typed arrays and other exotic host objects should be rejected.
  try {
    // ArrayBuffer view check covers TypedArray and DataView
    if (isArrayBufferViewSafe(object)) {
      throw new InvalidParameterError(
        "Unsupported typed-array or DataView in payload.",
      );
    }
  } catch {
    // If ArrayBuffer.isView throws (very exotic hosts), fall through to other checks
  }

  const ctorName = safeCtorName(object);
  if (
    ctorName === "Map" ||
    ctorName === "Set" ||
    ctorName === "Date" ||
    ctorName === "RegExp" ||
    ctorName === "ArrayBuffer" ||
    ctorName === "DataView" ||
    ctorName === "SharedArrayBuffer" ||
    ctorName === "WeakMap" ||
    ctorName === "WeakSet" ||
    ctorName === "Blob" ||
    ctorName === "File" ||
    ctorName === "URL"
  ) {
    throw new InvalidParameterError(
      `Unsupported object type in payload: ${String(ctorName ?? "Unknown")}`,
    );
  }

  // Use a WeakSet per top-level invocation to detect cycles.
  visited ??= new WeakSet<object>();
  if (visited.has(object as object)) {
    throw new InvalidParameterError("Circular reference detected in payload.");
  }
  visited.add(object as object);

  if (Array.isArray(object)) {
    // Map children using the same visited set so cycles across array/object are detected.
    const mapped = (object as readonly unknown[]).map((item) =>
      toNullProto(item, depth + 1, maxDepth, visited),
    );
    return mapped;
  }

  const out: Record<string, unknown> = Object.create(null);
  // iterate string keys only; ignore symbol-keyed properties to avoid
  // invoking exotic symbol-based traps or leaking internals
  for (const key of Object.keys(object as Record<string, unknown>)) {
    // Use safe property access to avoid invoking getters
    let value: unknown;
    try {
      const desc = Object.getOwnPropertyDescriptor(
        object as Record<string, unknown>,
        key,
      );
      if (
        desc &&
        (typeof desc.get === "function" || typeof desc.set === "function")
      ) {
        // Skip accessor properties to avoid executing untrusted getters
        continue;
      }
      if (desc && Object.hasOwn(desc, "value")) {
        const descValueValue = desc.value as unknown;
        value = descValueValue;
      } else {
        // Fallback, but guard in try/catch
        const objectValueRaw = (object as Record<string, unknown>)[key];
        const objectValue = objectValueRaw as unknown;
        value = objectValue as unknown;
      }
    } catch (error: unknown) {
      // If property access throws, skip it but log best-effort in dev
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Skipped property due to throwing getter",
          { key, error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* best-effort */
      }
      continue;
    }

    // Skip forbidden keys that could enable prototype pollution
    if (isForbiddenKey(key)) {
      continue;
    }

    // Additional defensive check for prototype-related keys
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }

    out[key] = toNullProto(value, depth + 1, maxDepth, visited);
  }

  return out;
}

// Helper: detect common localhost hostnames and IPv6 loopback forms.
function isHostnameLocalhost(hostname: string): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") return true;
  if (h.startsWith("127.")) return true; // 127.x.x.x
  if (h.startsWith("::ffff:127.")) return true; // IPv4-mapped IPv6
  return false;
}

// Iterative deep-freeze with node budget to avoid deep recursion and DoS via wide structures.
/* eslint-disable-next-line sonarjs/cognitive-complexity -- Iterative deep-freeze avoids recursion risks and requires controlled mutation locally. */
function deepFreeze<T>(
  object: T,
  nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET,
): T {
  if (!(object && typeof object === "object")) return object;

  // Quick guard: attempt to freeze shallowly first (best-effort)
  try {
    Object.freeze(object as unknown as object);
  } catch {
    // ignore errors from freezing exotic host objects
  }

  /* eslint-disable functional/no-let, functional/immutable-data, functional/prefer-readonly-type */
  // Iterative traversal stack (mutable local) — safe because this is internal state
  const stack: unknown[] = [object as unknown];
  const seen = new WeakSet<object>();
  let nodes = 0;

  while (stack.length > 0) {
    if (++nodes > nodeBudget) {
      // Budget exceeded; log and stop traversal to avoid CPU exhaustion
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze budget exceeded",
          { nodeBudget },
        );
      } catch {
        /* best-effort */
      }
      break;
    }

    const current = stack.pop();
    if (!current || typeof current !== "object") continue;
    if (seen.has(current as object)) continue;
    seen.add(current as object);

    try {
      try {
        Object.freeze(current as object);
      } catch {
        // ignore freeze errors
      }
      if (Array.isArray(current)) {
        for (const v of current) {
          if (v && typeof v === "object") stack.push(v);
        }
      } else {
        // Use Object.values to iterate own enumerable values (consistent with toNullProto)
        for (const v of Object.values(current as Record<string, unknown>)) {
          if (v && typeof v === "object") stack.push(v);
        }
      }
    } catch (error: unknown) {
      // Best effort logging
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze encountered error while traversing object",
          { error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* ignore */
      }
    }
  }
  /* eslint-enable functional/no-let, functional/immutable-data */

  return object;
}

// --- Public API ---

/* eslint-disable-next-line sonarjs/cognitive-complexity -- Multiple wire format validation and sanitization branches; splitting would harm auditability. */
export function sendSecurePostMessage(options: SecurePostMessageOptions): void {
  const { targetWindow, payload, targetOrigin } = options;
  const wireFormat = (options as SecurePostMessageOptions).wireFormat ?? "json";
  const sanitizeOutgoing =
    (options as SecurePostMessageOptions).sanitize !== false; // default true
  if (!targetWindow)
    throw new InvalidParameterError("targetWindow must be provided.");
  if (targetOrigin === "*")
    throw new InvalidParameterError("targetOrigin cannot be a wildcard ('*').");
  if (!targetOrigin || typeof targetOrigin !== "string")
    throw new InvalidParameterError("targetOrigin must be a specific string.");

  // Enforce absolute origin and prefer HTTPS (allow localhost for dev)
  try {
    const parsed = new URL(targetOrigin);
    // Enforce that an origin string does not include a path/search/hash
    if (
      (parsed.pathname && parsed.pathname !== "/") ||
      parsed.search ||
      parsed.hash
    ) {
      throw new InvalidParameterError(
        "targetOrigin must be a pure origin (no path, query, or fragment).",
      );
    }
    const isLocalhost = isHostnameLocalhost(parsed.hostname);
    if (parsed.origin === "null") {
      throw new InvalidParameterError("targetOrigin 'null' is not allowed.");
    }
    if (parsed.protocol !== "https:" && !isLocalhost) {
      throw new InvalidParameterError(
        "targetOrigin must use https: (localhost allowed for dev).",
      );
    }
  } catch (error: unknown) {
    // Log sanitized parse error and fail loudly per "Fail Loudly, Fail Safely" policy.
    try {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Invalid targetOrigin provided",
        {
          targetOrigin,
          error: sanitizeErrorForLogs(error),
        },
      );
    } catch {
      // best-effort logging; do not leak raw error details
    }
    throw new InvalidParameterError(
      "targetOrigin must be an absolute origin, e.g. 'https://example.com'.",
    );
  }

  // Handle wire formats
  if (wireFormat === "json") {
    // Serialize first to validate JSON-serializability and enforce size limits
    /* eslint-disable-next-line functional/no-let -- Local serialization variable; scoped to block */
    let serialized: string;
    try {
      const toSend = sanitizeOutgoing ? toNullProto(payload) : payload;
      serialized = JSON.stringify(toSend);
    } catch {
      // JSON.stringify throws TypeError on circular structures
      throw new InvalidParameterError("Payload must be JSON-serializable.");
    }

    // Enforce max payload bytes before sending
    const bytes = SHARED_ENCODER.encode(serialized);
    if (bytes.length > POSTMESSAGE_MAX_PAYLOAD_BYTES) {
      throw new InvalidParameterError(
        `Payload exceeds maximum size of ${POSTMESSAGE_MAX_PAYLOAD_BYTES} bytes.`,
      );
    }

    try {
      targetWindow.postMessage(serialized, targetOrigin);
    } catch (error: unknown) {
      if (error instanceof TypeError) {
        throw new InvalidParameterError("Payload must be JSON-serializable.");
      }
      throw error;
    }
    return;
  }

  if (wireFormat === "structured" || wireFormat === "auto") {
    // Structured: allow posting non-string data. 'auto' may be downgraded on receive.
    // By default we sanitize outgoing payloads to null-proto version to avoid prototype pollution.
    const allowTransferablesOutgoing = options.allowTransferables ?? false;
    const allowTypedArraysOutgoing = options.allowTypedArrays ?? false;

    // Fail-fast on incompatible options combination
    if (sanitizeOutgoing && allowTypedArraysOutgoing) {
      throw new InvalidParameterError(
        "Incompatible options: sanitize=true is incompatible with allowTypedArrays=true. " +
          "To send TypedArray/DataView/ArrayBuffer, set sanitize=false and ensure allowTypedArrays=true.",
      );
    }

    // Validate transferables before any processing
    try {
      validateTransferables(
        payload,
        allowTransferablesOutgoing,
        allowTypedArraysOutgoing,
      );
    } catch (error: unknown) {
      if (error instanceof TransferableNotAllowedError) {
        throw error; // Re-throw specific transferable errors
      }
      throw new InvalidParameterError(
        "Payload validation failed: " +
          String((error as Error)?.message ?? String(error)),
      );
    }

    if (sanitizeOutgoing) {
      try {
        const sanitized = toNullProto(payload);
        // sanitized is a JSON-safe structure (null-proto or primitives)
        targetWindow.postMessage(sanitized, targetOrigin);
        return;
      } catch (error: unknown) {
        if (error instanceof TransferableNotAllowedError) {
          throw error; // Re-throw transferable errors
        }
        const errorMessage =
          error instanceof Error ? error.message : `${String(error)}`;
        throw new InvalidParameterError(
          "Structured-clone payload contains unsupported host objects or circular references: " +
            errorMessage,
        );
      }
    }
    // If sanitize disabled, attempt to post as-is but transferables were already validated above
    try {
      // payload was validated for transferables above; assert safe typing for postMessage
      targetWindow.postMessage(payload, targetOrigin);
      return;
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      throw new InvalidParameterError(
        "Failed to post structured payload: ensure payload is structured-cloneable: " +
          errorMessage,
      );
    }
  }

  throw new InvalidParameterError("Unsupported wireFormat");
}

export function createSecurePostMessageListener(
  allowedOriginsOrOptions:
    | readonly string[]
    | CreateSecurePostMessageListenerOptions,
  onMessageOptional?: (data: unknown) => void,
): SecurePostMessageListener {
  /* eslint-disable functional/no-let -- Local parsing variables for parameter overloading; scoped to function */
  let allowedOrigins: readonly string[] | undefined,
    onMessage: (data: unknown) => void,
    validator:
      | ((d: unknown) => boolean)
      | Record<string, SchemaValue>
      | undefined;

  let optionsObject: CreateSecurePostMessageListenerOptions | undefined;
  /* eslint-enable functional/no-let */

  if (Array.isArray(allowedOriginsOrOptions)) {
    allowedOrigins = allowedOriginsOrOptions;
    if (!onMessageOptional) {
      throw new InvalidParameterError(
        "onMessage callback is required when passing allowed origins array.",
      );
    }
    onMessage = onMessageOptional as (data: unknown) => void;
  } else {
    optionsObject =
      allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    allowedOrigins = optionsObject.allowedOrigins;
    onMessage = optionsObject.onMessage;
    validator = optionsObject.validate;
  }

  // Production-time synchronous crypto availability check:
  checkCryptoAvailabilityForSecurityFeature("postMessage diagnostics", true);

  // In production, require explicit channel binding and a validator to avoid
  // creating a listener that accepts messages from any origin/source.
  const hasAllowedOrigins =
    Array.isArray(allowedOrigins) && allowedOrigins.length > 0;
  const hasExpectedSource =
    typeof optionsObject?.expectedSource !== "undefined";
  if (environment.isProduction && !(hasAllowedOrigins || hasExpectedSource)) {
    throw new InvalidConfigurationError(
      "createSecurePostMessageListener requires 'allowedOrigins' or 'expectedSource' in production.",
    );
  }

  // If production, require validator presence to force positive validation
  if (environment.isProduction && !validator) {
    throw new InvalidConfigurationError(
      "createSecurePostMessageListener requires 'validate' in production.",
    );
  }

  // Lock configuration at creation time to prevent TOCTOU attacks
  // Build canonical options object and freeze it to prevent mutation
  const finalOptions = (
    optionsObject
      ? { ...optionsObject, allowedOrigins: optionsObject.allowedOrigins ?? [] }
      : {
          allowedOrigins: allowedOrigins ?? [],
          onMessage,
          validate: validator,
          allowOpaqueOrigin: false,
          expectedSource: undefined,
          allowExtraProps: false,
          enableDiagnostics: false,
          freezePayload: true,
          wireFormat: "json",
          deepFreezeNodeBudget: DEFAULT_DEEP_FREEZE_NODE_BUDGET,
          allowTransferables: false,
          allowTypedArrays: false,
        }
  ) as CreateSecurePostMessageListenerOptions;
  Object.freeze(finalOptions);

  // Extract immutable locals to prevent runtime configuration changes
  const validatorLocal = finalOptions.validate;
  const expectedSourceLocal = finalOptions.expectedSource;
  const allowExtraPropertiesLocal = finalOptions.allowExtraProps ?? false;
  const freezePayloadLocal = finalOptions.freezePayload !== false;
  const enableDiagnosticsLocal = !!finalOptions.enableDiagnostics;
  const wireFormatLocal = finalOptions.wireFormat ?? "json";
  const allowTransferablesLocal = !!finalOptions.allowTransferables;
  const allowTypedArraysLocal = !!finalOptions.allowTypedArrays;
  const allowOpaqueOriginLocal = !!finalOptions.allowOpaqueOrigin;
  /* deepFreezeNodeBudgetLocal intentionally unused here; use finalOptions.deepFreezeNodeBudget where needed */

  // Normalize origins to canonical form to avoid mismatches like :443 vs default
  function normalizeOrigin(o: string): string {
    try {
      // Reuse shared URL normalization
      const norm = normalizeUrlOrigin(o);
      // Validate canonicalization by parsing norm
      const u = new URL(norm);
      if (u.origin === "null") throw new InvalidParameterError("opaque origin");
      const isLocalhost = isHostnameLocalhost(u.hostname);
      if (u.protocol !== "https:" && !isLocalhost)
        throw new InvalidParameterError("insecure origin");
      return norm;
    } catch {
      throw new InvalidParameterError(
        `Invalid allowed origin '${o}'. Use an absolute origin 'https://example.com' or 'http://localhost'.`,
      );
    }
  }

  // Build the canonical allowed origin set and an abort controller for the
  // event listener lifecycle. If any origin is invalid, collect them and
  // throw a single informative error.
  /* eslint-disable functional/no-let -- Local validation loop; scoped to function */
  let invalidOrigins: readonly string[] = [];
  const allowedOriginSet = new Set<string>();
  for (const o of allowedOrigins || []) {
    try {
      const n = normalizeOrigin(o);
      /* eslint-disable-next-line functional/immutable-data -- Local set building; safe operation */
      allowedOriginSet.add(n);
    } catch {
      invalidOrigins = [...invalidOrigins, o];
    }
  }
  /* eslint-enable functional/no-let */
  if (invalidOrigins.length > 0) {
    throw new InvalidParameterError(
      `Invalid allowedOrigins provided: ${invalidOrigins.join(", ")}`,
    );
  }

  const abortController = new AbortController();
  // Diagnostic budget to limit expensive fingerprinting on the failure path
  /* eslint-disable functional/no-let -- Local diagnostic state; scoped to function */
  let diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
  let diagnosticLastRefill = now();
  function canConsumeDiagnostic(): boolean {
    const n = now();
    if (n - diagnosticLastRefill > 60_000) {
      diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
      diagnosticLastRefill = n;
    }
    if (diagnosticBudget > 0) {
      diagnosticBudget -= 1;
      return true;
    }
    return false;
  }
  /* eslint-enable functional/no-let */

  // Module-scoped cache to avoid re-freezing identical object instances.
  function getDeepFreezeCache(): WeakSet<object> | undefined {
    try {
      // Use an internal well-known symbol to attach a cache to the deepFreeze
      const key = Symbol.for("__security_kit_deep_freeze_cache_v1");
      const holder = deepFreeze as unknown as Record<
        symbol,
        WeakSet<object> | undefined
      >;
      // Use nullish coalescing assignment when possible to avoid repeated lookups
      /* eslint-disable-next-line functional/immutable-data -- Local cache initialization; safe operation */
      holder[key] ??= new WeakSet<object>();
      return holder[key];
    } catch {
      return undefined;
    }
  }

  function freezePayloadIfNeeded(payload: unknown): void {
    const shouldFreeze = finalOptions.freezePayload !== false; // default true
    if (!shouldFreeze) return;
    if (payload == undefined || typeof payload !== "object") return;
    const asObject = payload as object;
    const cache = getDeepFreezeCache();
    const nodeBudget =
      finalOptions.deepFreezeNodeBudget ?? DEFAULT_DEEP_FREEZE_NODE_BUDGET;
    if (cache) {
      if (!cache.has(asObject)) {
        try {
          deepFreeze(asObject, nodeBudget);
        } catch (error: unknown) {
          try {
            secureDevelopmentLog(
              "warn",
              "postMessage",
              "deepFreeze failed or budget exceeded while freezing payload",
              { error: sanitizeErrorForLogs(error) },
            );
          } catch {
            /* best-effort */
          }
        }
        try {
          cache.add(asObject);
        } catch {
          /* ignore */
        }
      }
      return;
    }
    try {
      deepFreeze(asObject, nodeBudget);
    } catch (error: unknown) {
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze failed or budget exceeded while freezing payload",
          { error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* ignore */
      }
    }
  }

  const handler = (event: MessageEvent) => {
    // Validate origin and source using extracted helpers to reduce cognitive complexity
    if (!isEventOriginAllowlisted(event)) return;
    if (!isEventSourceExpected(event)) return;
    try {
      const data = parseMessageEventData(event);

      if (!validatorLocal) {
        // Defensive: validator should always be present due to creation-time checks
        secureDevelopmentLog(
          "error",
          "postMessage",
          "Message validator missing at runtime",
          {},
        );
        return;
      }

      const validationResult = _validatePayloadWithExtras(
        data,
        validatorLocal,
        allowExtraPropertiesLocal,
      );
      if (!validationResult.valid) {
        // Gate expensive fingerprinting behind diagnostics and a small budget to avoid DoS
        scheduleDiagnosticForFailedValidation(
          event.origin,
          validationResult.reason,
          data,
        );
        return;
      }

      // Freeze payload by default (immutable) with an identity cache to avoid
      // repeated work. Consumers can opt out with freezePayload: false.
      if (freezePayloadLocal) freezePayloadIfNeeded(data);
      // Build a small context object to give consumers access to event-level
      // details such as origin, source and ports. This keeps the onMessage
      // signature backwards-compatible (second param optional).
      const context: MessageListenerContext = {
        origin: event.origin,
        source: event.source,
        ports: event.ports as unknown as readonly MessagePort[] | undefined,
        event,
      };
      // Call the consumer in a small helper so this handler stays simple.
      invokeConsumerSafely(
        onMessage as (d: unknown, c?: unknown) => void,
        data,
        context,
      );
    } catch (error: unknown) {
      secureDevelopmentLog("error", "postMessage", "Listener handler error", {
        origin: event?.origin,
        error: sanitizeErrorForLogs(error),
      });
    }
  };

  function isEventOriginAllowlisted(event: MessageEvent): boolean {
    // Treat empty string and 'null' as opaque origin markers. By default we
    // reject opaque origins because they are hard to reason about. If the
    // listener explicitly opted into `allowOpaqueOrigin`, accept them and
    // skip canonical normalization checks.
    const incoming = typeof event.origin === "string" ? event.origin : "";
    const isOpaque = incoming === "" || incoming === "null";
    if (isOpaque) {
      if (!allowOpaqueOriginLocal) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message due to invalid origin format",
          {
            origin: incoming,
          },
        );
        return false;
      }
      // If opaque origins are allowed, skip normalization and allow the message
      // to proceed to other checks (e.g., expectedSource). This keeps the
      // explicit opt-in behavior while allowing reply-port based scenarios.
      return true;
    }

    try {
      if (!allowedOriginSet.has(normalizeOrigin(incoming))) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message from non-allowlisted origin",
          {
            origin: incoming,
          },
        );
        return false;
      }
    } catch (error: unknown) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message due to invalid origin format",
        {
          origin: incoming,
          error: sanitizeErrorForLogs(error),
        },
      );
      return false;
    }
    return true;
  }

  function isEventSourceExpected(event: MessageEvent): boolean {
    if (typeof expectedSourceLocal === "undefined") return true;
    const expected = expectedSourceLocal;
    // If expectedSource is a comparator function, call it
    if (typeof expected === "function") {
      try {
        const ok = (expected as (s: unknown) => boolean)(event.source);
        if (!ok) {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Dropped message from unexpected source (comparator mismatch)",
            {
              origin: event.origin,
            },
          );
        }
        return Boolean(ok);
      } catch (error: unknown) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message due to expectedSource comparator throwing",
          {
            origin: event.origin,
            error: sanitizeErrorForLogs(error),
          },
        );
        return false;
      }
    }
    // Otherwise do strict reference equality
    if (expected && event.source !== expected) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message from unexpected source (reference mismatch)",
        {
          origin: event.origin,
        },
      );
      return false;
    }
    return true;
  }

  // Schedule diagnostics for failed validation: use the diagnostic budget and
  // a salted fingerprint when available. This is extracted to keep handler
  // cognitive complexity under limits.
  function scheduleDiagnosticForFailedValidation(
    origin: string,
    reason: string | undefined,
    data: unknown,
  ): void {
    const enableDiagnostics = enableDiagnosticsLocal;
    if (
      !enableDiagnostics ||
      !canConsumeDiagnostic() ||
      _diagnosticsDisabledDueToNoCryptoInProduction
    ) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Message dropped due to failed validation",
        {
          origin,
          reason,
        },
      );
      return;
    }

    // Async helper: attempt to compute fingerprint and log it.
    const computeAndLog = async () => {
      try {
        await ensureCrypto();
      } catch {
        // No secure crypto available: respect production policy and avoid
        // creating low-entropy fingerprints. If in production, disable
        // future diagnostics that would rely on non-crypto fallbacks.
        try {
          if (environment.isProduction)
            _diagnosticsDisabledDueToNoCryptoInProduction = true;
        } catch {
          /* ignore */
        }
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Message dropped due to failed validation",
          { origin, reason },
        );
        return;
      }

      // Attempt fingerprinting and log result (async). Errors handled per-case.
      getPayloadFingerprint(data)
        .then((fp) => {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            { origin, reason, fingerprint: fp },
          );
        })
        .catch(() => {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            { origin, reason },
          );
        });
    };

    // Fire-and-forget the async helper; errors are handled internally.
    void computeAndLog();
  }

  function parseMessageEventData(event: MessageEvent): unknown {
    const wireFormat = wireFormatLocal;

    // If structured/auto, allow non-string data when appropriate
    if (wireFormat === "structured") {
      // Accept structured clone payloads but sanitize and enforce host-type disallow rules
      if (event.data === null || typeof event.data !== "object") {
        // primitive types are acceptable via structured clone
        return event.data;
      }
      // Use locked configuration values from creation time

      // Use strict transferable validation
      try {
        validateTransferables(
          event.data,
          allowTransferablesLocal,
          allowTypedArraysLocal,
        );
      } catch (error: unknown) {
        if (error instanceof TransferableNotAllowedError) {
          throw error; // Re-throw specific transferable errors
        }
        throw new InvalidParameterError(
          "Received payload validation failed: " +
            String((error as Error)?.message ?? error),
        );
      }

      // Special handling for ArrayBuffers when allowed
      if (allowTypedArraysLocal && event.data instanceof ArrayBuffer) {
        return event.data; // Return ArrayBuffer as-is without toNullProto processing
      }

      // Convert to null-prototype and enforce depth/forbidden keys
      return toNullProto(event.data, 0, POSTMESSAGE_MAX_PAYLOAD_DEPTH);
    }

    if (wireFormat === "auto") {
      // auto: accept structured clone only for same-origin messages; otherwise require JSON string
      try {
        const sameOrigin =
          normalizeUrlOrigin(event.origin) ===
          normalizeUrlOrigin(location.origin);
        if (
          sameOrigin &&
          event.data !== null &&
          typeof event.data === "object"
        ) {
          return toNullProto(event.data, 0, POSTMESSAGE_MAX_PAYLOAD_DEPTH);
        }
      } catch {
        // fall back to JSON handling below
      }
      // else treat as JSON string path
    }

    // Default JSON path: require string
    if (typeof event.data !== "string") {
      // Reject non-string payloads to avoid structured clone cycles and ambiguous typing
      throw new InvalidParameterError(
        "postMessage payload must be a JSON string",
      );
    }
    const byteLength = SHARED_ENCODER.encode(event.data).length;
    if (byteLength > POSTMESSAGE_MAX_PAYLOAD_BYTES) {
      secureDevelopmentLog("warn", "postMessage", "Dropped oversized payload", {
        origin: event.origin,
      });
      throw new InvalidParameterError("Payload exceeds maximum allowed size.");
    }
    // eslint-disable-next-line functional/no-let -- Local parsed variable; scoped to function
    let parsed: unknown;
    try {
      parsed = JSON.parse(event.data);
    } catch {
      throw new InvalidParameterError("Invalid JSON in postMessage");
    }
    // Convert to null-prototype objects and enforce depth + forbidden keys
    return toNullProto(parsed, 0, POSTMESSAGE_MAX_PAYLOAD_DEPTH);
  }

  // Use globalThis.addEventListener so the listener works both on the main
  // thread (window) and in worker contexts (self/globalThis). Cast to any to
  // avoid TypeScript errors in non-DOM environments.
  // Prefer `window.addEventListener` when available (tests often stub `window`).
  const globalTarget: { addEventListener?: unknown } =
    typeof window !== "undefined" &&
    (window as unknown as { addEventListener?: unknown }).addEventListener
      ? (window as unknown as { addEventListener?: unknown })
      : (globalThis as unknown as { addEventListener?: unknown });
  try {
    (
      globalTarget as unknown as {
        addEventListener: (
          type: string,
          listener: EventListenerOrEventListenerObject,
          options?: AddEventListenerOptions,
        ) => void;
      }
    ).addEventListener(
      "message",
      handler as EventListenerOrEventListenerObject,
      { signal: abortController.signal } as AddEventListenerOptions,
    );
  } catch (e) {
    // If addEventListener is not available on the selected target, surface a clear error.
    throw new InvalidConfigurationError(
      "Global event target does not support addEventListener",
    );
  }
  return { destroy: () => abortController.abort() };
}

// --- Internal Helpers ---

// Deterministic, stable JSON serialization used for fingerprinting only.
function stableStringify(
  object: unknown,
  maxDepth = POSTMESSAGE_MAX_PAYLOAD_DEPTH,
  nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET,
):
  | { readonly ok: true; readonly s: string }
  | { readonly ok: false; readonly reason: string } {
  /* eslint-disable functional/no-let -- Local serialization state; scoped to function */
  const seen = new WeakSet<object>();
  let nodes = 0;

  function norm(o: unknown, depth: number): unknown {
    if (++nodes > nodeBudget) throw new InvalidParameterError("budget");
    if (o === null || typeof o !== "object") return o;
    if (depth > maxDepth) throw new InvalidParameterError("depth");
    if (seen.has(o as object)) throw new InvalidParameterError("circular");
    seen.add(o as object);
    if (Array.isArray(o))
      return (o as readonly unknown[]).map((v) => norm(v, depth + 1));
    const keys = Object.keys(o as Record<string, unknown>).sort((a, b) =>
      a.localeCompare(b),
    );
    /* eslint-disable functional/immutable-data -- Building new null-proto object; local writes to fresh object are safe */
    const result = Object.create(null) as Record<string, unknown>;
    for (const k of keys) {
      result[k] = norm((o as Record<string, unknown>)[k], depth + 1);
    }
    /* eslint-enable functional/immutable-data */
    return result;
  }

  try {
    const normalized = norm(object, 0);
    return { ok: true, s: JSON.stringify(normalized) };
  } catch (error: unknown) {
    return { ok: false, reason: String((error as Error)?.message ?? "error") };
  }
  /* eslint-enable functional/no-let */
}

// Memoized salt initialization promise to avoid races when multiple callers
// request a salt concurrently.
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for salt memoization; audited */
let _payloadFingerprintSaltPromise: Promise<Uint8Array> | undefined;

// Salt used to make fingerprints non-linkable across process restarts.
// Generated lazily using secure RNG when available.
const FINGERPRINT_SALT_LENGTH = 16;
// Use `undefined` as the uninitialised sentinel to align with lint rules
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for salt memoization; audited */
let _payloadFingerprintSalt: Uint8Array | undefined = undefined;
// If secure crypto is not available in production, disable diagnostics that
// rely on non-crypto fallbacks.
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for diagnostics flag; audited */
let _diagnosticsDisabledDueToNoCryptoInProduction = false;

// Cooldown period in milliseconds to prevent thundering herd on repeated failures
// when generating the fingerprint salt. This avoids repeated rapid retries
// hitting the underlying crypto initialization when it's failing transiently.
const SALT_FAILURE_COOLDOWN_MS = 5_000;
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for failure backoff; audited */
let _saltGenerationFailureTimestamp: number | undefined;

async function ensureFingerprintSalt(): Promise<Uint8Array> {
  if (typeof _payloadFingerprintSalt !== "undefined" && _payloadFingerprintSalt)
    return _payloadFingerprintSalt;

  // If a generation promise is already in-flight, reuse it to avoid races.
  if (typeof _payloadFingerprintSaltPromise !== "undefined")
    return _payloadFingerprintSaltPromise;

  // If we recently observed a failure to generate a salt, fail-fast for a
  // short cooldown period to avoid thundering-herd retries against a failing
  // underlying initialization (e.g., ensureCrypto()).
  if (
    typeof _saltGenerationFailureTimestamp !== "undefined" &&
    now() - _saltGenerationFailureTimestamp < SALT_FAILURE_COOLDOWN_MS
  ) {
    throw new CryptoUnavailableError(
      "Salt generation failed recently; on cooldown.",
    );
  }
  // Fast synchronous availability check: if in production and crypto is missing,
  // we fail fast rather than relying on time-based fallback.
  checkCryptoAvailabilityForSecurityFeature(
    "fingerprint salt generation",
    true,
  );

  _payloadFingerprintSaltPromise = (async () => {
    try {
      const crypto = await ensureCrypto();
      const salt = new Uint8Array(FINGERPRINT_SALT_LENGTH);
      crypto.getRandomValues(salt);
      _payloadFingerprintSalt = salt;
      // Success: clear any previous failure timestamp so future attempts won't be blocked
      _saltGenerationFailureTimestamp = undefined;
      return salt;
    } catch (error: unknown) {
      // Record failure timestamp to engage cooldown and avoid thundering herd
      _saltGenerationFailureTimestamp = now();

      // No secure crypto available: enforce security constitution.
      if (environment.isProduction) {
        try {
          _diagnosticsDisabledDueToNoCryptoInProduction = true;
        } catch {
          /* ignore */
        }
        try {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Secure crypto unavailable in production; disabling diagnostics that rely on non-crypto fallbacks",
            { error: sanitizeErrorForLogs(error) },
          );
        } catch {
          /* ignore */
        }
        throw new CryptoUnavailableError();
      }

      // Non-production (development/test) fallback: log and produce a
      // deterministic, time-based salt to preserve testability.
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Falling back to non-crypto fingerprint salt (dev/test only)",
          {
            error: sanitizeErrorForLogs(error),
          },
        );
      } catch {
        // best-effort logging
      }
      const timeEntropy =
        String(Date.now()) +
        String(
          typeof performance !== "undefined" &&
            typeof performance.now === "function"
            ? performance.now()
            : 0,
        );
      const buf = new Uint8Array(FINGERPRINT_SALT_LENGTH);
      /* eslint-disable functional/no-let, functional/immutable-data -- Local loop index and buffer initialization; scoped */
      for (let index = 0; index < buf.length; index++) {
        buf[index] = timeEntropy.charCodeAt(index % timeEntropy.length) & 0xff;
      }
      /* eslint-enable functional/no-let, functional/immutable-data */

      _payloadFingerprintSalt = buf;
      // Clear failure timestamp on fallback success so we don't block future attempts
      _saltGenerationFailureTimestamp = undefined;
      return buf;
    }
  })();

  try {
    const saltResult = await _payloadFingerprintSaltPromise;
    return saltResult;
  } finally {
    // clear promise so subsequent calls go fast (salt is cached)

    _payloadFingerprintSaltPromise = undefined;
  }
}

// Helper: compute an initial allowed origin from an incoming MessageEvent.
// This mirrors the small, well-audited logic used by workers to lock the
// inbound origin at initialization time. We expose it so callers can reuse
// identical semantics instead of re-implementing them.
export function computeInitialAllowedOrigin(
  event?: MessageEvent,
): string | undefined {
  try {
    const origin =
      event && typeof event.origin === "string" ? event.origin : "";
    if (origin) return origin;
    if (
      typeof location !== "undefined" &&
      location &&
      typeof location.origin === "string"
    )
      return location.origin;
    return undefined;
  } catch {
    return undefined;
  }
}

// Helper: check whether an incoming MessageEvent should be accepted given a
// locked origin (if any). This implements the conservative fallback behavior
// used by workers: if a locked origin exists, require a match; otherwise
// fall back to matching location.origin when possible; if origin information
// is unavailable, require the presence of a reply MessagePort to avoid
// accepting anonymous posts.
export function isEventAllowedWithLock(
  event: MessageEvent,
  lockedOrigin?: string,
): boolean {
  try {
    const incomingOrigin = typeof event.origin === "string" ? event.origin : "";

    if (typeof lockedOrigin === "string" && lockedOrigin !== "") {
      return incomingOrigin === lockedOrigin;
    }

    const fallbackOrigin =
      typeof location !== "undefined" ? location.origin : "";
    if (incomingOrigin !== "" && fallbackOrigin !== "") {
      return incomingOrigin === fallbackOrigin;
    }

    // If we can't establish any origin information, only accept messages that
    // include a reply port — this avoids processing anonymous posts.
    return !!(event?.ports && event.ports.length > 0);
  } catch {
    return false;
  }
}

async function getPayloadFingerprint(data: unknown): Promise<string> {
  // Canonicalize sanitized payload for deterministic fingerprints
  const sanitized: unknown = (() => {
    try {
      return toNullProto(data, 0, POSTMESSAGE_MAX_PAYLOAD_DEPTH);
    } catch {
      // If sanitization fails, fall back to raw representation for diagnostics only
      return data;
    }
  })();
  const stable = stableStringify(
    sanitized,
    POSTMESSAGE_MAX_PAYLOAD_DEPTH,
    DEFAULT_DEEP_FREEZE_NODE_BUDGET,
  );
  if (!stable.ok) {
    // If canonicalization fails, return an explicit error token in prod or a fallback in dev
    if (environment.isProduction)
      throw new EncodingError(
        "Fingerprinting failed due to resource constraints",
      );
    // dev/test fallback: use best-effort raw string truncated

    const s = JSON.stringify(sanitized).slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);
    return computeFingerprintFromString(s);
  }
  // Encode as UTF-8 bytes and truncate by bytes to avoid splitting multi-byte chars
  const fullBytes = SHARED_ENCODER.encode(stable.s);
  const payloadBytes = fullBytes.slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);
  return computeFingerprintFromBytes(payloadBytes);
}

// Common fingerprint computation logic shared between functions
async function computeFingerprintFromBytes(
  payloadBytes: Uint8Array,
): Promise<string> {
  // eslint-disable-next-line functional/no-let -- Local salt buffer variable; scoped to function
  let saltBuf: Uint8Array | undefined;
  try {
    saltBuf = await ensureFingerprintSalt();
  } catch {
    if (environment.isProduction)
      throw new InvalidConfigurationError("Fingerprinting unavailable");
  }

  try {
    const crypto = await ensureCrypto();
    const subtle = (crypto as Crypto & { readonly subtle?: SubtleCrypto })
      .subtle;
    if (subtle && typeof subtle.digest === "function" && saltBuf) {
      const saltArray = saltBuf;
      const input = new Uint8Array(saltArray.length + payloadBytes.length);
      input.set(saltArray, 0);
      input.set(payloadBytes, saltArray.length);
      const digest = await subtle.digest("SHA-256", input.buffer);
      return arrayBufferToBase64(digest).slice(0, 12);
    }
  } catch {
    /* fall through to non-crypto fallback */
  }

  // Fallback: salted non-crypto rolling hash (development/test only)
  if (!saltBuf) return "FINGERPRINT_ERR";
  const sb = saltBuf;
  // eslint-disable-next-line functional/no-let -- Local accumulator for hash computation; scoped to function
  let accumulator = 2166136261 >>> 0; // FNV-1a init
  for (const byte of sb) {
    accumulator = ((accumulator ^ byte) * 16777619) >>> 0;
  }
  for (const byte of payloadBytes) {
    accumulator = ((accumulator ^ byte) * 16777619) >>> 0;
  }
  return accumulator.toString(16).padStart(8, "0");
}

// Extracted helper so stable/canonical fallback can use the same compute logic
async function computeFingerprintFromString(s: string): Promise<string> {
  // Work with UTF-8 bytes and prefer crypto.subtle when available.
  const fullBytes = SHARED_ENCODER.encode(s);
  const payloadBytes = fullBytes.slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);

  return computeFingerprintFromBytes(payloadBytes);
}

export function _validatePayload(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
): { readonly valid: boolean; readonly reason?: string } {
  if (typeof validator === "function") {
    try {
      return { valid: validator(data) };
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Validator function threw: ${error instanceof Error ? error.message : ""}`,
      };
    }
  }
  const isPlainOrNullObject = (o: unknown): o is Record<string, unknown> => {
    if (o === null || typeof o !== "object") return false;
    const p = Object.getPrototypeOf(o) as object | null | undefined;
    return p === Object.prototype || p === null;
  };
  if (!isPlainOrNullObject(data)) {
    return { valid: false, reason: `Expected object, got ${typeof data}` };
  }
  const plainData = data;
  const keys = Object.keys(plainData);
  if (keys.some((k) => isForbiddenKey(k))) {
    return { valid: false, reason: "Forbidden property name present" };
  }
  for (const [key, expectedType] of Object.entries(validator)) {
    if (!Object.hasOwn(plainData, key)) {
      return { valid: false, reason: `Missing property '${key}'` };
    }
    const value = plainData[key];
    const actualType = Array.isArray(value) ? "array" : typeof value;
    if (actualType !== expectedType) {
      return {
        valid: false,
        reason: `Property '${key}' has wrong type. Expected ${expectedType}, got ${actualType}`,
      };
    }
  }
  return { valid: true };
}

export function _validatePayloadWithExtras(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
  allowExtraProperties = false,
): { readonly valid: boolean; readonly reason?: string } {
  // Validator function path: execute safely and return boolean result.
  if (typeof validator === "function") {
    try {
      return { valid: Boolean((validator as (d: unknown) => boolean)(data)) };
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Validator function threw: ${error instanceof Error ? error.message : ""}`,
      };
    }
  }

  // For schema validators, reuse the base validation first.
  const base = _validatePayload(data, validator);
  if (!base.valid) return base;

  // If extra properties are allowed, we're done.
  if (allowExtraProperties) return { valid: true };

  // Otherwise, ensure no unexpected keys are present.
  const allowed = new Set(Object.keys(validator));
  const plainData = data as Record<string, unknown>;
  for (const k of Object.keys(plainData)) {
    if (!allowed.has(k)) {
      return { valid: false, reason: `Unexpected property '${k}'` };
    }
  }

  return { valid: true };
}

// Test-only accessors for internal helpers. Guarded by a runtime check to avoid
// leaking internals in production builds. These are only available when the
// build defines `__TEST__` and the runtime allows test APIs via dev-guards.
export const __test_internals:
  | {
      readonly toNullProto: (
        object: unknown,
        depth?: number,
        maxDepth?: number,
      ) => unknown;
      readonly getPayloadFingerprint: (data: unknown) => Promise<string>;
      readonly ensureFingerprintSalt: () => Promise<Uint8Array>;
      readonly deepFreeze: <T>(object: T) => T;
    }
  | undefined =
  typeof __TEST__ !== "undefined" && __TEST__
    ? (() => {
        // runtime guard for test-only API usage
        // use require to avoid static circular imports in some bundlers
        try {
          // Prefer CommonJS require when available (test runners often support it).
          // Fall back to throwing a helpful error if require is not available.
          // We purposely avoid dynamic import here because this factory is synchronous.
          // Tests should run in an environment that supports require or set the
          // SECURITY_KIT_ALLOW_TEST_APIS flag.

          try {
            const globalRecord = globalThis as unknown as Record<
              string,
              unknown
            >;
            const request = globalRecord["require"];
            if (typeof request !== "function") {
              throw new Error(
                "Cannot load test internals: require() not available. Ensure your test environment supports CommonJS require or enable SECURITY_KIT_ALLOW_TEST_APIS.",
              );
            }
            /* eslint-disable-next-line @typescript-eslint/no-unsafe-call -- Runtime guard ensures request is a function; test environment only */
            const developmentGuards = (request as Function)(
              "./development-guards",
            ) as {
              readonly assertTestApiAllowed: () => void;
            };
            developmentGuards.assertTestApiAllowed();
          } catch {
            // Ignore require errors in test environment setup
          }

          const testExports = {
            toNullProto: toNullProto as (
              object: unknown,
              depth?: number,
              maxDepth?: number,
            ) => unknown,
            getPayloadFingerprint: getPayloadFingerprint as (
              data: unknown,
            ) => Promise<string>,
            ensureFingerprintSalt:
              ensureFingerprintSalt as () => Promise<Uint8Array>,
            deepFreeze: deepFreeze as <T>(object: T) => T,
          };
          return testExports;
        } catch (error: unknown) {
          // If test internals cannot be exposed, return undefined to avoid exposing internals in prod builds.
          try {
            secureDevelopmentLog(
              "warn",
              "postMessage",
              "Test internals not exposed",
              {
                error: sanitizeErrorForLogs(error),
              },
            );
          } catch {
            /* best-effort */
          }
          return undefined;
        }
      })()
    : undefined;

// Runtime-guarded test helpers: these call a runtime dev-guard to ensure they
// are not used in production by accident. Prefer these in unit tests instead
// of relying on build-time __TEST__ macros which may not be available in all
// execution environments used by test runners.
function _assertTestApiAllowedInline(): void {
  try {
    if (!environment.isProduction) return;
  } catch {
    return;
  }
  const environmentAllow =
    typeof process !== "undefined" &&
    process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
  const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
    "__SECURITY_KIT_ALLOW_TEST_APIS"
  ];
  if (environmentAllow || globalAllow) return;
  throw new Error(
    "Test-only APIs are disabled in production. Set SECURITY_KIT_ALLOW_TEST_APIS=true or set globalThis.__SECURITY_KIT_ALLOW_TEST_APIS = true to explicitly allow.",
  );
}

export function __test_getPayloadFingerprint(data: unknown): Promise<string> {
  _assertTestApiAllowedInline();
  return getPayloadFingerprint(data);
}

export function __test_ensureFingerprintSalt(): Promise<Uint8Array> {
  _assertTestApiAllowedInline();
  return ensureFingerprintSalt();
}

export function __test_toNullProto(
  object: unknown,
  depth?: number,
  maxDepth?: number,
): unknown {
  _assertTestApiAllowedInline();
  return toNullProto(
    object,
    depth ?? 0,
    maxDepth ?? POSTMESSAGE_MAX_PAYLOAD_DEPTH,
  );
}

export function __test_deepFreeze<T>(object: T): T {
  _assertTestApiAllowedInline();
  return deepFreeze(object);
}

export function __test_resetForUnitTests(): void {
  _assertTestApiAllowedInline();
  _payloadFingerprintSalt = undefined;
  _diagnosticsDisabledDueToNoCryptoInProduction = false;
  _saltGenerationFailureTimestamp = undefined;
}

// Test-only helpers to inspect and manipulate the salt failure timestamp for
// adversarial tests that simulate cooldown behavior. Guarded by the same
// runtime test API check used above.
export function __test_getSaltFailureTimestamp(): number | undefined {
  _assertTestApiAllowedInline();
  return _saltGenerationFailureTimestamp;
}

export function __test_setSaltFailureTimestamp(v: number | undefined): void {
  _assertTestApiAllowedInline();
  _saltGenerationFailureTimestamp = v;
}
