// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Hardened utilities for secure cross-context communication using `postMessage`.
 * @module
 */

import {
  InvalidParameterError,
  InvalidConfigurationError,
  sanitizeErrorForLogs,
} from "./errors";
import { ensureCrypto } from "./state";
import { secureDevLog, _arrayBufferToBase64 } from "./utils";
import { SHARED_ENCODER } from "./encoding";
import { isForbiddenKey } from "./constants";
import { environment } from "./environment";
import { normalizeOrigin as normalizeUrlOrigin } from "./url";

// --- Interfaces and Types ---

export interface SecurePostMessageOptions {
  targetWindow: Window;
  payload: unknown;
  targetOrigin: string;
}

export interface SecurePostMessageListener {
  destroy: () => void;
}

export type SchemaValue = "string" | "number" | "boolean" | "object" | "array";

export type CreateSecurePostMessageListenerOptions = {
  allowedOrigins: string[];
  onMessage: (data: unknown) => void;
  validate?: ((d: unknown) => boolean) | Record<string, SchemaValue>;
  // New hardening options
  allowOpaqueOrigin?: boolean; // default false
  expectedSource?: Window | MessagePort; // optional stronger binding
  allowExtraProps?: boolean; // default false when using schema
  enableDiagnostics?: boolean; // default false; gates fingerprints in prod
  // freezePayload: when true (default), the sanitized payload will be deeply frozen
  // before being passed to the consumer. When false, callers accept responsibility
  // for not mutating the payload.
  freezePayload?: boolean;
};

// --- Constants ---

export const POSTMESSAGE_MAX_PAYLOAD_BYTES = 32 * 1024;
export const POSTMESSAGE_MAX_PAYLOAD_DEPTH = 8;

// Small default limits for diagnostics to prevent DoS via expensive hashing
const DEFAULT_DIAGNOSTIC_BUDGET = 5; // fingerprints per minute

// --- Internal Security Helpers ---

/**
 * Converts objects to null-prototype objects to prevent prototype pollution attacks.
 * Also enforces depth limits and strips forbidden keys.
 * @param obj - The object to convert
 * @param depth - Current depth in the object tree
 * @param maxDepth - Maximum allowed depth
 * @returns The sanitized object with null prototype
 */
function toNullProto(
  obj: unknown,
  depth = 0,
  maxDepth = POSTMESSAGE_MAX_PAYLOAD_DEPTH,
): unknown {
  if (depth > maxDepth) {
    throw new InvalidParameterError(
      `Payload depth exceeds limit of ${maxDepth}`,
    );
  }

  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => toNullProto(item, depth + 1, maxDepth));
  }

  const out = Object.create(null);
  // iterate string keys only; ignore symbol-keyed properties to avoid
  // invoking exotic symbol-based traps or leaking runtime internals
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    // Use safe property access to avoid invoking getters
    let value: unknown;
    try {
      const desc = Object.getOwnPropertyDescriptor(
        obj as Record<string, unknown>,
        key,
      );
      if (
        desc &&
        (typeof desc.get === "function" || typeof desc.set === "function")
      ) {
        // Skip accessor properties to avoid executing untrusted getters
        continue;
      }
      value = (obj as Record<string, unknown>)[key];
    } catch {
      // If property access throws, skip it
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

    out[key] = toNullProto(value, depth + 1, maxDepth);
  }

  return out;
}

function deepFreeze<T>(obj: T): T {
  // Use a temporary WeakSet to track objects currently being processed to
  // avoid infinite recursion on cyclic structures.
  if (!(obj && typeof obj === "object")) return obj;

  // _processing guard is stored on the function object to avoid creating a
  // new WeakSet on every call when nested recursion occurs.
  const holder = deepFreeze as unknown as { _processing?: WeakSet<object> };
  let created = false;
  if (!holder._processing) {
    holder._processing = new WeakSet<object>();
    created = true;
  }
  const processing = holder._processing!;

  // If we're already processing this object, bail out to avoid cycles.
  if (processing.has(obj as object)) {
    if (created) delete holder._processing;
    return obj;
  }

  processing.add(obj as object);
  try {
    try {
      Object.freeze(obj as object);
    } catch {
      // ignore freeze errors on exotic objects
    }
    if (Array.isArray(obj)) {
      for (const v of obj) deepFreeze(v as T);
    } else {
      for (const v of Object.values(obj as object)) deepFreeze(v as T);
    }
  } finally {
    processing.delete(obj as object);
    if (created) delete holder._processing;
  }
  return obj;
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
    const isLocalhost =
      parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    if (parsed.origin === "null") {
      throw new InvalidParameterError("targetOrigin 'null' is not allowed.");
    }
    if (parsed.protocol !== "https:" && !isLocalhost) {
      throw new InvalidParameterError(
        "targetOrigin must use https: (localhost allowed for dev).",
      );
    }
  } catch (err) {
    // Log sanitized parse error and fail loudly per "Fail Loudly, Fail Safely" policy.
    try {
      secureDevLog("warn", "postMessage", "Invalid targetOrigin provided", {
        targetOrigin,
        error: sanitizeErrorForLogs(err),
      });
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
  allowedOriginsOrOptions: string[] | CreateSecurePostMessageListenerOptions,
  onMessageOptional?: (data: unknown) => void,
): SecurePostMessageListener {
  let allowedOrigins: string[],
    onMessage: (data: unknown) => void,
    validator:
      | ((d: unknown) => boolean)
      | Record<string, SchemaValue>
      | undefined;

  if (Array.isArray(allowedOriginsOrOptions)) {
    allowedOrigins = allowedOriginsOrOptions;
    onMessage = onMessageOptional as (data: unknown) => void;
  } else {
    allowedOrigins = allowedOriginsOrOptions.allowedOrigins;
    onMessage = allowedOriginsOrOptions.onMessage;
    validator = allowedOriginsOrOptions.validate;
  }
  // In production, require explicit channel binding to avoid creating a
  // listener that accepts messages from any origin/source. This defaults to
  // a safe-fail approach (fail loudly) per the Security Constitution.
  {
    const hasAllowedOrigins =
      Array.isArray(allowedOrigins) && allowedOrigins.length > 0;
    const opts =
      allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    const hasExpectedSource = !!opts?.expectedSource;
    if (environment.isProduction && !(hasAllowedOrigins || hasExpectedSource)) {
      throw new InvalidConfigurationError(
        "createSecurePostMessageListener requires 'allowedOrigins' or 'expectedSource' in production.",
      );
    }
  }
  // Normalize origins to canonical form to avoid mismatches like :443 vs default
  function normalizeOrigin(o: string): string {
    try {
      // Reuse shared URL normalization but enforce https/localhost policies here.
      const norm = normalizeUrlOrigin(o);
      const u = new URL(o);
      if (u.origin === "null") throw new Error("opaque origin");
      const isLocalhost =
        u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol !== "https:" && !isLocalhost)
        throw new Error("insecure origin");
      // Ensure we return the canonical origin form (protocol//host[:port])
      return norm;
    } catch {
      throw new InvalidParameterError(
        `Invalid allowed origin '${o}'. Use an absolute origin 'https://example.com' or 'http://localhost'.`,
      );
    }
  }

  const allowedOriginSet = new Set(allowedOrigins.map(normalizeOrigin));
  const abortController = new AbortController();

  // Diagnostic budget to limit expensive fingerprinting on the failure path
  let diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
  let diagnosticLastRefill = performance.now();
  function canConsumeDiagnostic(): boolean {
    const now = performance.now();
    if (now - diagnosticLastRefill > 60_000) {
      diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
      diagnosticLastRefill = now;
    }
    if (diagnosticBudget > 0) {
      diagnosticBudget -= 1;
      return true;
    }
    return false;
  }

  // Module-scoped cache to avoid re-freezing identical object instances.
  // Stored outside the handler to keep memory use proportional to live objects.
  function getDeepFreezeCache(): WeakSet<object> | undefined {
    try {
      const holder = deepFreeze as unknown as { _cache?: WeakSet<object> };
      holder._cache ??= new WeakSet<object>();
      return holder._cache;
    } catch {
      return undefined;
    }
  }

  function freezePayloadIfNeeded(
    opts: CreateSecurePostMessageListenerOptions,
    payload: unknown,
  ): void {
    const shouldFreeze = opts.freezePayload !== false; // default true
    if (!shouldFreeze) return;
    if (payload == null || typeof payload !== "object") return;
    const cache = getDeepFreezeCache();
    if (cache) {
      if (!cache.has(payload)) {
        try {
          deepFreeze(payload);
        } catch {
          /* ignore */
        }
        try {
          cache.add(payload);
        } catch {
          /* ignore */
        }
      }
      return;
    }
    try {
      deepFreeze(payload);
    } catch {
      /* ignore */
    }
  }

  const handler = (event: MessageEvent) => {
    // Validate origin and source using extracted helpers to reduce cognitive complexity
    if (!isEventOriginAllowlisted(event)) return;
    if (!isEventSourceExpected(event)) return;
    try {
      const data = parseMessageEventData(event);

      if (!validator) {
        // Require a validator by default for positive validation
        throw new InvalidParameterError(
          "Message validator is required by policy.",
        );
      }

      const allowExtraProps =
        typeof (
          allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions
        ).allowExtraProps === "boolean"
          ? (allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions)
              .allowExtraProps!
          : false;

      const validationResult = _validatePayloadWithExtras(
        data,
        validator,
        allowExtraProps,
      );
      if (!validationResult.valid) {
        // Gate expensive fingerprinting behind diagnostics and a small budget to avoid DoS
        scheduleDiagnosticForFailedValidation(
          allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions,
          event.origin,
          validationResult.reason,
          data,
        );
        return;
      }

      // Freeze payload by default (immutable) with an identity cache to avoid
      // repeated work. Consumers can opt out with freezePayload: false.
      freezePayloadIfNeeded(
        allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions,
        data,
      );
      // Call the consumer. If the consumer returns a promise that rejects,
      // attach a rejection handler so we can sanitize and log the error and
      // avoid unhandled promise rejections in environments where consumers
      // implement async handlers.
      try {
        const result = onMessage(data);
        // Attach an async rejection handler without awaiting to preserve
        // synchronous handler behavior for callers.
        Promise.resolve(result).catch((asyncErr) => {
          try {
            secureDevLog("error", "postMessage", "Listener handler error", {
              origin: event.origin,
              error: sanitizeErrorForLogs(asyncErr),
            });
          } catch {
            /* best-effort logging */
          }
        });
      } catch (err) {
        // Synchronous consumer errors are handled by the outer catch below,
        // but handle here to ensure sanitized logging too.
        secureDevLog("error", "postMessage", "Listener handler error", {
          origin: event.origin,
          error: sanitizeErrorForLogs(err),
        });
      }
    } catch (err) {
      secureDevLog("error", "postMessage", "Listener handler error", {
        origin: event.origin,
        error: sanitizeErrorForLogs(err),
      });
    }
  };

  function isEventOriginAllowlisted(event: MessageEvent): boolean {
    // Opaque origin handling
    if (event.origin === "null") {
      secureDevLog(
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
        secureDevLog(
          "warn",
          "postMessage",
          "Dropped message from non-allowlisted origin",
          {
            origin: event.origin,
          },
        );
        return false;
      }
    } catch (err) {
      secureDevLog(
        "warn",
        "postMessage",
        "Dropped message due to invalid origin format",
        {
          origin: event.origin,
          error: sanitizeErrorForLogs(err),
        },
      );
      return false;
    }
    return true;
  }

  function isEventSourceExpected(event: MessageEvent): boolean {
    const opts =
      allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    if (typeof opts.expectedSource === "undefined") return true;
    if (opts.expectedSource && event.source !== opts.expectedSource) {
      secureDevLog(
        "warn",
        "postMessage",
        "Dropped message from unexpected source",
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
    opts: CreateSecurePostMessageListenerOptions,
    origin: string,
    reason: string | undefined,
    data: unknown,
  ): void {
    const enableDiagnostics = !!opts.enableDiagnostics;
    if (
      !enableDiagnostics ||
      !canConsumeDiagnostic() ||
      _diagnosticsDisabledDueToNoCryptoInProd
    ) {
      secureDevLog(
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
            _diagnosticsDisabledDueToNoCryptoInProd = true;
        } catch {
          /* ignore */
        }
        secureDevLog(
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
          secureDevLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            { origin, reason, fingerprint: fp },
          );
        })
        .catch(() => {
          secureDevLog(
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
    const byteLen = SHARED_ENCODER.encode(event.data).length;
    if (byteLen > POSTMESSAGE_MAX_PAYLOAD_BYTES) {
      secureDevLog("warn", "postMessage", "Dropped oversized payload", {
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
let _payloadFingerprintSalt: Uint8Array | null = null;
// If secure crypto is not available in production, disable diagnostics that
// rely on non-crypto fallbacks to avoid producing low-entropy fingerprints.
let _diagnosticsDisabledDueToNoCryptoInProd = false;

async function ensureFingerprintSalt(): Promise<Uint8Array> {
  if (_payloadFingerprintSalt) return _payloadFingerprintSalt;
  try {
    const crypto = await ensureCrypto();
    const salt = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    crypto.getRandomValues(salt);
    _payloadFingerprintSalt = salt;
    return salt;
  } catch (err) {
    // No secure crypto available. Fail loudly but produce a deterministic, time-based
    // salt to avoid throwing in environments where fingerprinting must continue.
    // Per the security constitution, we avoid using Math.random() and log the event.
    try {
      secureDevLog(
        "warn",
        "postMessage",
        "Falling back to non-crypto fingerprint salt",
        {
          error: sanitizeErrorForLogs(err),
        },
      );
    } catch {
      // best-effort logging
    }
    // If we're in production, disable diagnostics that rely on low-entropy
    // fallbacks to avoid producing linkable or low-quality fingerprints.
    try {
      if (environment.isProduction)
        _diagnosticsDisabledDueToNoCryptoInProd = true;
    } catch {
      /* ignore */
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
    for (let i = 0; i < buf.length; i++) {
      buf[i] = timeEntropy.charCodeAt(i % timeEntropy.length) & 0xff;
    }
    _payloadFingerprintSalt = buf;
    return buf;
  }
}

async function getPayloadFingerprint(data: unknown): Promise<string> {
  try {
    const s = JSON.stringify(data).slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);
    const saltBuf = await ensureFingerprintSalt();
    try {
      const crypto = await ensureCrypto();
      const subtle = (crypto as Crypto & { subtle?: SubtleCrypto }).subtle;
      if (subtle && typeof subtle.digest === "function") {
        const payloadBytes = SHARED_ENCODER.encode(s);
        const saltArr = saltBuf;
        const input = new Uint8Array(saltArr.length + payloadBytes.length);
        input.set(saltArr, 0);
        input.set(payloadBytes, saltArr.length);
        const digest = await subtle.digest("SHA-256", input.buffer);
        return _arrayBufferToBase64(digest).slice(0, 12);
      }
    } catch {
      /* fall through */
    }
    // Fallback: salted non-crypto rolling hash
    if (!saltBuf) return "FINGERPRINT_ERR";
    const sb = saltBuf;
    let acc = 2166136261 >>> 0; // FNV-1a init
    for (const byte of sb) {
      acc = ((acc ^ byte) * 16777619) >>> 0;
    }
    for (let i = 0; i < s.length; i++) {
      acc = ((acc ^ s.charCodeAt(i)) * 16777619) >>> 0;
    }
    return acc.toString(16).padStart(8, "0");
  } catch {
    return "FINGERPRINT_ERR";
  }
}

export function _validatePayload(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
): { valid: boolean; reason?: string } {
  if (typeof validator === "function") {
    try {
      return { valid: validator(data) };
    } catch (e) {
      return {
        valid: false,
        reason: `Validator function threw: ${e instanceof Error ? e.message : ""}`,
      };
    }
  }
  const isPlainOrNullObject = (o: unknown): o is Record<string, unknown> => {
    if (o === null || typeof o !== "object") return false;
    const p = Object.getPrototypeOf(o);
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
  allowExtraProps = false,
): { valid: boolean; reason?: string } {
  // Validator function path: execute safely and return boolean result.
  if (typeof validator === "function") {
    try {
      return { valid: Boolean((validator as (d: unknown) => boolean)(data)) };
    } catch (e) {
      return {
        valid: false,
        reason: `Validator function threw: ${e instanceof Error ? e.message : ""}`,
      };
    }
  }

  // For schema validators, reuse the base validation first.
  const base = _validatePayload(data, validator);
  if (!base.valid) return base;

  // If extra properties are allowed, we're done.
  if (allowExtraProps) return { valid: true };

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
      toNullProto: (obj: unknown, depth?: number, maxDepth?: number) => unknown;
      getPayloadFingerprint: (data: unknown) => Promise<string>;
      ensureFingerprintSalt: () => Promise<Uint8Array>;
      deepFreeze: <T>(obj: T) => T;
    }
  | undefined =
  typeof __TEST__ !== "undefined" && __TEST__
    ? (() => {
        // runtime guard for test-only API usage
        // use require to avoid static circular imports in some bundlers
        const { assertTestApiAllowed } = require("./dev-guards");
        assertTestApiAllowed();
        return {
          toNullProto: toNullProto as any,
          getPayloadFingerprint: getPayloadFingerprint as any,
          ensureFingerprintSalt: ensureFingerprintSalt as any,
          deepFreeze: deepFreeze as any,
        };
      })()
    : undefined;

// Runtime-guarded test helpers: these call a runtime dev-guard to ensure they
// are not used in production by accident. Prefer these in unit tests instead
// of relying on build-time __TEST__ macros which may not be available in all
// execution environments used by test runners.
function _assertTestApiAllowedInline(): void {
  // Mirror of dev-guards.assertTestApiAllowed to avoid requiring the module
  // at runtime during tests. This keeps the runtime check local and avoids
  // loader resolution differences in test environments.
  try {
    if (!environment.isProduction) return;
  } catch {
    return;
  }
  const envAllow =
    typeof process !== "undefined" &&
    process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
  const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
    "__SECURITY_KIT_ALLOW_TEST_APIS"
  ];
  if (envAllow || globalAllow) return;
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
  obj: unknown,
  depth?: number,
  maxDepth?: number,
): unknown {
  _assertTestApiAllowedInline();
  return toNullProto(
    obj,
    depth ?? 0,
    maxDepth ?? POSTMESSAGE_MAX_PAYLOAD_DEPTH,
  );
}

export function __test_deepFreeze<T>(obj: T): T {
  _assertTestApiAllowedInline();
  return deepFreeze(obj);
}

export function __test_resetForUnitTests(): void {
  _assertTestApiAllowedInline();
  _payloadFingerprintSalt = null;
  _diagnosticsDisabledDueToNoCryptoInProd = false;
}
