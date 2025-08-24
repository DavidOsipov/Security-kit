// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Hardened utilities for secure cross-context communication using `postMessage`.
 * @module
 */

import { InvalidParameterError } from "./errors";
import { ensureCrypto } from "./state";
import {
  secureDevLog,
  sanitizeErrorForLogs,
  _arrayBufferToBase64,
} from "./utils";

const ENCODER = new TextEncoder();

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
};

// --- Constants ---

export const POSTMESSAGE_MAX_PAYLOAD_BYTES = 32 * 1024;
export const POSTMESSAGE_MAX_PAYLOAD_DEPTH = 8;
export const POSTMESSAGE_FORBIDDEN_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

// --- Public API ---

export function sendSecurePostMessage(options: SecurePostMessageOptions): void {
  const { targetWindow, payload, targetOrigin } = options;
  if (!targetWindow)
    throw new InvalidParameterError("targetWindow must be provided.");
  if (targetOrigin === "*")
    throw new InvalidParameterError("targetOrigin cannot be a wildcard ('*').");
  if (!targetOrigin || typeof targetOrigin !== "string")
    throw new InvalidParameterError("targetOrigin must be a specific string.");

  try {
    targetWindow.postMessage(JSON.stringify(payload), targetOrigin);
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
    validator: any;

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
    allowedOrigins.some((o) => typeof o !== "string" || o === "*")
  ) {
    throw new InvalidParameterError(
      "allowedOrigins must be an array of specific origin strings.",
    );
  }
  if (typeof onMessage !== "function") {
    throw new InvalidParameterError("onMessage must be a function.");
  }

  const allowedOriginSet = new Set(allowedOrigins);
  const abortController = new AbortController();

  const handler = (event: MessageEvent) => {
    if (!allowedOriginSet.has(event.origin)) {
      secureDevLog(
        "warn",
        "postMessage",
        "Dropped message from non-allowlisted origin",
        { origin: event.origin },
      );
      return;
    }
    try {
      const data = parseMessageEventData(event);

      if (validator) {
        const validationResult = _validatePayload(data, validator);
        if (!validationResult.valid) {
          void getPayloadFingerprint(data).then((fp) => {
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
          });
          return;
        }
      }
      onMessage(data);
    } catch (err) {
      secureDevLog("error", "postMessage", "Listener handler error", {
        origin: event.origin,
        error: sanitizeErrorForLogs(err),
      });
    }
  };

  function parseMessageEventData(event: MessageEvent): unknown {
    if (typeof event.data === "string") {
      if (event.data.length > POSTMESSAGE_MAX_PAYLOAD_BYTES) {
        secureDevLog("warn", "postMessage", "Dropped oversized payload", {
          origin: event.origin,
        });
        throw new Error("OVERSIZED_PAYLOAD");
      }
      return JSON.parse(event.data);
    }
    return event.data;
  }

  window.addEventListener("message", handler, {
    signal: abortController.signal,
  });
  return { destroy: () => abortController.abort() };
}

// --- Internal Helpers ---

async function getPayloadFingerprint(data: unknown): Promise<string> {
  try {
    const s = JSON.stringify(data).slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);
    try {
      const crypto = await ensureCrypto();
      const subtle = (crypto as any).subtle;
      if (subtle?.digest) {
        const digest = await subtle.digest("SHA-256", ENCODER.encode(s));
        return _arrayBufferToBase64(digest).slice(0, 12);
      }
    } catch {
      /* fall through */
    }
    let acc = 0;
    for (let i = 0; i < s.length; i++) acc = (acc * 31 + s.charCodeAt(i)) >>> 0;
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
  if (typeof data !== "object" || data === null) {
    return { valid: false, reason: `Expected object, got ${typeof data}` };
  }
  if (Object.getPrototypeOf(data) !== Object.prototype) {
    return { valid: false, reason: "Prototype pollution attempt detected" };
  }
  const objMap = new Map(Object.entries(data));
  if (
    objMap.has("__proto__") ||
    objMap.has("prototype") ||
    objMap.has("constructor")
  ) {
    return { valid: false, reason: "Forbidden property name present" };
  }
  for (const [key, expectedType] of Object.entries(validator)) {
    if (!objMap.has(key))
      return { valid: false, reason: `Missing property '${key}'` };
    const value = objMap.get(key);
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
