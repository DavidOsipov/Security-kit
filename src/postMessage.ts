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
  sanitizeErrorForLogs,
} from "./errors";
import { ensureCrypto } from "./state";
import {
  secureDevLog as secureDevelopmentLog,
  _arrayBufferToBase64,
} from "./utils";
import { SHARED_ENCODER } from "./encoding";
import { isForbiddenKey } from "./constants";
import { environment } from "./environment";
import { normalizeOrigin as normalizeUrlOrigin } from "./url";

// --- Interfaces and Types ---

export interface SecurePostMessageOptions {
  readonly targetWindow: Window;
  readonly payload: unknown;
  readonly targetOrigin: string;
}

export interface SecurePostMessageListener {
  readonly destroy: () => void;
}

export type SchemaValue = "string" | "number" | "boolean" | "object" | "array";

export type CreateSecurePostMessageListenerOptions = {
  readonly allowedOrigins: readonly string[];
  readonly onMessage: (data: unknown) => void;
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
};

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
  return typeof performance !== "undefined" && typeof performance.now === "function"
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
    const g = (globalThis as unknown) as { crypto?: unknown };
    if (!g || typeof g.crypto === "undefined") return false;
    const c = g.crypto as unknown as { getRandomValues?: unknown };
    return !!(c && typeof c.getRandomValues === "function");
  } catch {
    return false;
  }
}

// --- Internal Security Helpers ---

/**
 * Converts objects to null-prototype objects to prevent prototype pollution attacks.
 * Also enforces depth limits and strips forbidden keys.
 */
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
    if (ArrayBuffer.isView(object as any)) {
      throw new InvalidParameterError("Unsupported typed-array or DataView in payload.");
    }
  } catch {
    // If ArrayBuffer.isView throws (very exotic hosts), fall through to other checks
  }

  const ctorName = (object as any)?.constructor?.name;
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
    const res = (object as unknown[]).map((item) =>
      toNullProto(item, depth + 1, maxDepth, visited),
    );
    return res;
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
      if (desc && Object.prototype.hasOwnProperty.call(desc, "value")) {
        value = (desc as PropertyDescriptor & { readonly value?: unknown }).value as unknown;
      } else {
        // Fallback, but guard in try/catch
        value = (object as Record<string, unknown>)[key] as unknown;
      }
    } catch (err) {
      // If property access throws, skip it but log best-effort in dev
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Skipped property due to throwing getter",
          { key, error: sanitizeErrorForLogs(err) },
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
function deepFreeze<T>(object: T, nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET): T {
  if (!(object && typeof object === "object")) return object;

  // Quick guard: attempt to freeze shallowly first (best-effort)
  try {
    Object.freeze(object as unknown as object);
  } catch {
    // ignore freeze errors on exotic objects
  }

  // Iterative traversal stack
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
        for (const v of Object.values(current as object)) {
          if (v && typeof v === "object") stack.push(v);
        }
      }
    } catch (err) {
      // Best effort logging
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze encountered error while traversing object",
          { error: sanitizeErrorForLogs(err) },
        );
      } catch {
        /* ignore */
      }
    }
  }

  return object;
}

// --- Public API ---

export function sendSecurePostMessage(options: SecurePostMessageOptions): void {
  const { targetWindow, payload, targetOrigin } = options;
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
    if ((parsed.pathname && parsed.pathname !== "/") || parsed.search || parsed.hash) {
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
  } catch (error) {
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

  // Serialize first to validate JSON-serializability and enforce size limits
  let serialized: string;
  try {
    serialized = JSON.stringify(payload);
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
  } catch (error) {
    if (error instanceof TypeError) {
      throw new InvalidParameterError("Payload must be JSON-serializable.");
    }
    throw error;
  }
}

export function createSecurePostMessageListener(
  allowedOriginsOrOptions:
    | readonly string[]
    | CreateSecurePostMessageListenerOptions,
  onMessageOptional?: (data: unknown) => void,
): SecurePostMessageListener {
  let allowedOrigins: readonly string[] | undefined,
    onMessage: (data: unknown) => void,
    validator:
      | ((d: unknown) => boolean)
      | Record<string, SchemaValue>
      | undefined;

  let optionsObj: CreateSecurePostMessageListenerOptions | undefined;

  if (Array.isArray(allowedOriginsOrOptions)) {
    allowedOrigins = allowedOriginsOrOptions;
    if (!onMessageOptional) {
      throw new InvalidParameterError("onMessage callback is required when passing allowed origins array.");
    }
    onMessage = onMessageOptional as (data: unknown) => void;
  } else {
    optionsObj = allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    allowedOrigins = optionsObj.allowedOrigins;
    onMessage = optionsObj.onMessage;
    validator = optionsObj.validate;
  }

  // Production-time synchronous crypto availability check:
  if (environment.isProduction && !syncCryptoAvailable()) {
    // Diagnostics which rely on secure crypto are disabled in this environment.
    try {
      _diagnosticsDisabledDueToNoCryptoInProduction = true;
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Secure crypto unavailable in production environment; diagnostics disabled.",
        {},
      );
    } catch {
      /* best-effort */
    }
    // Fail-fast: production requires crypto for our security guarantees.
    throw new CryptoUnavailableError("Secure crypto (crypto.getRandomValues) required in production.");
  }

  // In production, require explicit channel binding and a validator to avoid
  // creating a listener that accepts messages from any origin/source.
  const hasAllowedOrigins = Array.isArray(allowedOrigins) && allowedOrigins.length > 0;
  const hasExpectedSource = !!(optionsObj && typeof optionsObj.expectedSource !== "undefined");
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

  // Normalize origins to canonical form to avoid mismatches like :443 vs default
  function normalizeOrigin(o: string): string {
    try {
      // Reuse shared URL normalization
      const norm = normalizeUrlOrigin(o);
      // Validate canonicalization by parsing norm
      const u = new URL(norm);
      if (u.origin === "null") throw new Error("opaque origin");
      const isLocalhost = isHostnameLocalhost(u.hostname);
      if (u.protocol !== "https:" && !isLocalhost) throw new Error("insecure origin");
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
  const invalidOrigins: string[] = [];
  const allowedOriginSet = new Set<string>();
  for (const o of (allowedOrigins || [])) {
    try {
      const n = normalizeOrigin(o);
      allowedOriginSet.add(n);
    } catch {
      invalidOrigins.push(o);
    }
  }
  if (invalidOrigins.length > 0) {
    throw new InvalidParameterError(
      `Invalid allowedOrigins provided: ${invalidOrigins.join(", ")}`,
    );
  }

  const abortController = new AbortController();
  // Diagnostic budget to limit expensive fingerprinting on the failure path
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

  // Module-scoped cache to avoid re-freezing identical object instances.
  function getDeepFreezeCache(): WeakSet<object> | undefined {
    try {
      const holder = deepFreeze as unknown as { _cache?: WeakSet<object> };
      (holder as any)._cache ??= new WeakSet<object>();
      return (holder as any)._cache as WeakSet<object>;
    } catch {
      return undefined;
    }
  }

  function freezePayloadIfNeeded(
    options: CreateSecurePostMessageListenerOptions,
    payload: unknown,
  ): void {
    const shouldFreeze = options.freezePayload !== false; // default true
    if (!shouldFreeze) return;
    if (payload == undefined || typeof payload !== "object") return;
    const cache = getDeepFreezeCache();
    const nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET;
    if (cache) {
      if (!cache.has(payload as object)) {
        try {
          deepFreeze(payload, nodeBudget);
        } catch (err) {
          try {
            secureDevelopmentLog(
              "warn",
              "postMessage",
              "deepFreeze failed or budget exceeded while freezing payload",
              { error: sanitizeErrorForLogs(err) },
            );
          } catch {
            /* best-effort */
          }
        }
        try {
          cache.add(payload as object);
        } catch {
          /* ignore */
        }
      }
      return;
    }
    try {
      deepFreeze(payload, nodeBudget);
    } catch (err) {
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze failed or budget exceeded while freezing payload",
          { error: sanitizeErrorForLogs(err) },
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

      if (!validator) {
        // Defensive: in case validator was removed from optionsObj at runtime
        secureDevelopmentLog("error", "postMessage", "Message validator missing at runtime", {});
        return;
      }

      const allowExtraProperties =
        typeof (optionsObj as CreateSecurePostMessageListenerOptions | undefined)?.allowExtraProps === "boolean"
          ? (optionsObj as CreateSecurePostMessageListenerOptions).allowExtraProps!
          : false;

      const validationResult = _validatePayloadWithExtras(
        data,
        validator,
        allowExtraProperties,
      );
      if (!validationResult.valid) {
        // Gate expensive fingerprinting behind diagnostics and a small budget to avoid DoS
        scheduleDiagnosticForFailedValidation(
          (optionsObj as CreateSecurePostMessageListenerOptions) || ({} as CreateSecurePostMessageListenerOptions),
          event.origin,
          validationResult.reason,
          data,
        );
        return;
      }

      // Freeze payload by default (immutable) with an identity cache to avoid
      // repeated work. Consumers can opt out with freezePayload: false.
      if (optionsObj) freezePayloadIfNeeded(optionsObj, data);
      // Call the consumer. If the consumer returns a promise that rejects,
      // attach a rejection handler so we can sanitize and log the error and
      // avoid unhandled promise rejections in environments where consumers
      // implement async handlers.
      try {
        const result = onMessage(data);
        Promise.resolve(result).catch((asyncError) => {
          try {
            secureDevelopmentLog(
              "error",
              "postMessage",
              "Listener handler error",
              {
                origin: event.origin,
                error: sanitizeErrorForLogs(asyncError),
              },
            );
          } catch {
            /* best-effort logging */
          }
        });
      } catch (error) {
        secureDevelopmentLog("error", "postMessage", "Listener handler error", {
          origin: event.origin,
          error: sanitizeErrorForLogs(error),
        });
      }
    } catch (error) {
      secureDevelopmentLog("error", "postMessage", "Listener handler error", {
        origin: event?.origin,
        error: sanitizeErrorForLogs(error),
      });
    }
  };

  function isEventOriginAllowlisted(event: MessageEvent): boolean {
    // Opaque origin handling
    if (event.origin === "null") {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message from opaque origin 'null'",
        {
          origin: event.origin,
        },
      );
      return false;
    }
    try {
      if (!allowedOriginSet.has(normalizeOrigin(event.origin))) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message from non-allowlisted origin",
          {
            origin: event.origin,
          },
        );
        return false;
      }
    } catch (error) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message due to invalid origin format",
        {
          origin: event.origin,
          error: sanitizeErrorForLogs(error),
        },
      );
      return false;
    }
    return true;
  }

  function isEventSourceExpected(event: MessageEvent): boolean {
    const options =
      (allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions) || optionsObj;
    const expected = options?.expectedSource;
    if (typeof expected === "undefined") return true;
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
      } catch (err) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message due to expectedSource comparator throwing",
          {
            origin: event.origin,
            error: sanitizeErrorForLogs(err),
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
    options: CreateSecurePostMessageListenerOptions,
    origin: string,
    reason: string | undefined,
    data: unknown,
  ): void {
    const enableDiagnostics = !!options.enableDiagnostics;
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
    let parsed: unknown;
    try {
      parsed = JSON.parse(event.data);
    } catch {
      throw new InvalidParameterError("Invalid JSON in postMessage");
    }
    // Convert to null-prototype objects and enforce depth + forbidden keys
    return toNullProto(parsed, 0, POSTMESSAGE_MAX_PAYLOAD_DEPTH);
  }

  window.addEventListener("message", handler, {
    signal: abortController.signal,
  });
  return { destroy: () => abortController.abort() };
}

// --- Internal Helpers ---

// Salt used to make fingerprints non-linkable across process restarts.
// Generated lazily using secure RNG when available.
const FINGERPRINT_SALT_LENGTH = 16;
// Use `undefined` as the uninitialised sentinel to align with lint rules
let _payloadFingerprintSalt: Uint8Array | undefined = undefined;
// If secure crypto is not available in production, disable diagnostics that
// rely on non-crypto fallbacks.
let _diagnosticsDisabledDueToNoCryptoInProduction = false;

async function ensureFingerprintSalt(): Promise<Uint8Array> {
  if (typeof _payloadFingerprintSalt !== "undefined" && _payloadFingerprintSalt)
    return _payloadFingerprintSalt;
  // Fast synchronous availability check: if in production and crypto is missing,
  // we fail fast rather than relying on time-based fallback.
  if (environment.isProduction && !syncCryptoAvailable()) {
    try {
      _diagnosticsDisabledDueToNoCryptoInProduction = true;
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Secure crypto unavailable in production; disabling diagnostics that rely on non-crypto fallbacks",
        {},
      );
    } catch {
      /* best-effort */
    }
    throw new CryptoUnavailableError();
  }

  try {
    const crypto = await ensureCrypto();
    const salt = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    crypto.getRandomValues(salt);
    _payloadFingerprintSalt = salt;
    return salt;
  } catch (error) {
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
        typeof performance !== "undefined" && typeof performance.now === "function"
          ? performance.now()
          : 0,
      );
    const buf = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    for (let index = 0; index < buf.length; index++) {
      buf[index] = timeEntropy.charCodeAt(index % timeEntropy.length) & 0xff;
    }
    _payloadFingerprintSalt = buf;
    return buf;
  }
}

async function getPayloadFingerprint(data: unknown): Promise<string> {
  const s = JSON.stringify(data).slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);
  let saltBuf: Uint8Array | undefined;
  try {
    saltBuf = await ensureFingerprintSalt();
  } catch (err) {
    if (environment.isProduction) throw err;
    // else: continue to attempt a non-crypto fallback
  }

  try {
    const crypto = await ensureCrypto();
    const subtle = (crypto as Crypto & { readonly subtle?: SubtleCrypto }).subtle;
    if (subtle && typeof subtle.digest === "function" && saltBuf) {
      const payloadBytes = SHARED_ENCODER.encode(s);
      const saltArray = saltBuf;
      const input = new Uint8Array(saltArray.length + payloadBytes.length);
      input.set(saltArray, 0);
      input.set(payloadBytes, saltArray.length);
      const digest = await subtle.digest("SHA-256", input.buffer);
      return _arrayBufferToBase64(digest).slice(0, 12);
    }
  } catch {
    /* fall through to non-crypto fallback */
  }

  // Fallback: salted non-crypto rolling hash (development/test only)
  if (!saltBuf) return "FINGERPRINT_ERR";
  const sb = saltBuf;
  let accumulator = 2166136261 >>> 0; // FNV-1a init
  for (const byte of sb) {
    accumulator = ((accumulator ^ byte) * 16777619) >>> 0;
  }
  for (let index = 0; index < s.length; index++) {
    accumulator = ((accumulator ^ s.charCodeAt(index)) * 16777619) >>> 0;
  }
  return accumulator.toString(16).padStart(8, "0");
}

export function _validatePayload(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
): { readonly valid: boolean; readonly reason?: string } {
  if (typeof validator === "function") {
    try {
      return { valid: validator(data) };
    } catch (error) {
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
    if (!Object.prototype.hasOwnProperty.call(plainData, key)) {
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
    } catch (error) {
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
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const developmentGuards = typeof require === "function"
            ? require("./development-guards") as {
                readonly assertTestApiAllowed: () => void;
              }
            : ((): never => {
                throw new Error("Cannot load test internals: require() not available. Ensure your test environment supports CommonJS require or enable SECURITY_KIT_ALLOW_TEST_APIS.");
              })();

          developmentGuards.assertTestApiAllowed();

          /* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment */
          const testExports = {
            toNullProto: toNullProto as any,
            getPayloadFingerprint: getPayloadFingerprint as any,
            ensureFingerprintSalt: ensureFingerprintSalt as any,
            deepFreeze: deepFreeze as any,
          };
          /* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment */
          return testExports;
        } catch (err) {
          // If test internals cannot be exposed, return undefined to avoid exposing internals in prod builds.
          try {
            secureDevelopmentLog("warn", "postMessage", "Test internals not exposed", {
              error: sanitizeErrorForLogs(err),
            });
          } catch {
            /* best-effort */
          }
          // eslint-disable-next-line @typescript-eslint/no-unsafe-return
          return undefined as any;
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
}
