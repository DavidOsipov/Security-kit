// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Hardened utilities for secure cross-context communication using `postMessage`.
 * @module
 */

import { InvalidParameterError, sanitizeErrorForLogs } from "./errors";
import { ensureCrypto } from "./state";
import { secureDevLog, _arrayBufferToBase64 } from "./utils";
import { SHARED_ENCODER } from "./encoding";

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
};

// --- Constants ---

export const POSTMESSAGE_MAX_PAYLOAD_BYTES = 32 * 1024;
export const POSTMESSAGE_MAX_PAYLOAD_DEPTH = 8;
export const POSTMESSAGE_FORBIDDEN_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

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
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    // Skip forbidden keys that could enable prototype pollution
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(key)) {
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
  if (obj && typeof obj === "object") {
    try {
      Object.freeze(obj as object);
    } catch {
      // ignore freeze errors on exotic objects
    }
    if (Array.isArray(obj)) {
      for (const v of obj as unknown as Array<unknown>) deepFreeze(v as T);
    } else {
      for (const v of Object.values(obj as object)) deepFreeze(v as T);
    }
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
  } catch (e) {
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

  if (
    !Array.isArray(allowedOrigins) ||
    allowedOrigins.some((o) => typeof o !== "string")
  ) {
    throw new InvalidParameterError(
      "allowedOrigins must be an array of origin strings.",
    );
  }
  if (typeof onMessage !== "function") {
    throw new InvalidParameterError("onMessage must be a function.");
  }

  // Normalize origins to canonical form to avoid mismatches like :443 vs default
  function normalizeOrigin(o: string): string {
    try {
      const u = new URL(o);
      if (u.origin === "null") throw new Error("opaque origin");
      // Enforce https except for localhost
      const isLocalhost =
        u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol !== "https:" && !isLocalhost)
        throw new Error("insecure origin");
      return u.origin;
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

  const handler = (event: MessageEvent) => {
    // Opaque origin handling
    if (event.origin === "null") {
      // Drop opaque origins by default
      secureDevLog(
        "warn",
        "postMessage",
        "Dropped message from opaque origin 'null'",
        {
          origin: event.origin,
        },
      );
      return;
    }

    try {
      if (!allowedOriginSet.has(normalizeOrigin(event.origin))) {
        secureDevLog(
          "warn",
          "postMessage",
          "Dropped message from non-allowlisted origin",
          { origin: event.origin },
        );
        return;
      }
    } catch (err) {
      secureDevLog(
        "warn",
        "postMessage",
        "Dropped message due to invalid origin format",
        {
          origin: event.origin,
        },
      );
      return;
    }

    // If expectedSource provided, ensure the event.source matches
    if (
      typeof (allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions)
        .expectedSource !== "undefined"
    ) {
      const opts =
        allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
      if (opts.expectedSource && event.source !== opts.expectedSource) {
        secureDevLog(
          "warn",
          "postMessage",
          "Dropped message from unexpected source",
          {
            origin: event.origin,
          },
        );
        return;
      }
    }
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
        const enableDiagnostics = !!(
          allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions
        ).enableDiagnostics;
        if (enableDiagnostics && canConsumeDiagnostic()) {
          try {
            queueMicrotask(() => {
              getPayloadFingerprint(data)
                .then((fp) => {
                  secureDevLog(
                    "warn",
                    "postMessage",
                    "Message dropped due to failed validation",
                    {
                      origin: event.origin,
                      reason: validationResult.reason,
                      fingerprint: fp,
                    },
                  );
                })
                .catch(() => {
                  /* ignore */
                });
            });
          } catch {
            /* ignore scheduling errors */
          }
        } else {
          secureDevLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            {
              origin: event.origin,
              reason: validationResult.reason,
            },
          );
        }
        return;
      }

      // Deep-freeze sanitized payload to enforce immutability
      onMessage(deepFreeze(data));
    } catch (err) {
      secureDevLog("error", "postMessage", "Listener handler error", {
        origin: event.origin,
        error: sanitizeErrorForLogs(err),
      });
    }
  };

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

async function ensureFingerprintSalt(): Promise<Uint8Array> {
  if (_payloadFingerprintSalt) return _payloadFingerprintSalt;
  try {
    const crypto = await ensureCrypto();
    const salt = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    crypto.getRandomValues(salt);
    _payloadFingerprintSalt = salt;
    return salt;
  } catch {
    // Fallback: non-cryptographic seed, still better than raw payload
    const s = String(Date.now()) + Math.random();
    const buf = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    for (let i = 0; i < buf.length; i++) {
      buf[i] = s.charCodeAt(i % s.length) & 0xff;
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
      if (subtle?.digest) {
        const payloadBytes = SHARED_ENCODER.encode(s);
        const input = new Uint8Array(
          (saltBuf as Uint8Array).length + payloadBytes.length,
        );
        input.set(saltBuf as Uint8Array, 0);
        input.set(payloadBytes, (saltBuf as Uint8Array).length);
        const digest = await subtle.digest("SHA-256", input.buffer);
        return _arrayBufferToBase64(digest).slice(0, 12);
      }
    } catch {
      /* fall through */
    }
    // Fallback: salted non-crypto rolling hash
    if (!saltBuf) return "FINGERPRINT_ERR";
    let acc = 2166136261 >>> 0; // FNV-1a init
    for (let i = 0; i < saltBuf.length; i++) {
      acc = ((acc ^ saltBuf[i]) * 16777619) >>> 0;
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
  const keys = Object.keys(data);
  if (keys.some((k) => POSTMESSAGE_FORBIDDEN_KEYS.has(k))) {
    return { valid: false, reason: "Forbidden property name present" };
  }
  for (const [key, expectedType] of Object.entries(validator)) {
    if (!Object.prototype.hasOwnProperty.call(data, key)) {
      return { valid: false, reason: `Missing property '${key}'` };
    }
    const value = (data as Record<string, unknown>)[key];
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

function _validatePayloadWithExtras(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
  allowExtraProps = false,
): { valid: boolean; reason?: string } {
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

  const base = _validatePayload(data, validator);
  if (!base.valid) return base;

  if (!allowExtraProps) {
    if (data && typeof data === "object") {
      const allowed = new Set(Object.keys(validator));
      for (const k of Object.keys(data as Record<string, unknown>)) {
        if (!allowed.has(k)) {
          return { valid: false, reason: `Unexpected property '${k}'` };
        }
      }
    }
  }
  return { valid: true };
}
