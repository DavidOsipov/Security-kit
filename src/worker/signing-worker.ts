// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Module-style worker for performing HMAC signing in a separate thread.

import { SHARED_ENCODER } from "../encoding";
import type { InitMessage, SignRequest } from "../protocol";
import {
  bytesToBase64,
  secureWipeWrapper,
  isLikelyBase64,
  isLikelyBase64Url,
} from "../encoding-utils";
import { getHandshakeConfig, setHandshakeConfig } from "../config";
import { secureDevLog as secureDevelopmentLog } from "../utils";
import { sanitizeErrorForLogs } from "../errors";
import {
  createSecurePostMessageListener,
  isEventAllowedWithLock,
} from "../postMessage";
import type { NonceFormat } from "../constants";

// --- State Management ---

/**
 * Defines the complete, immutable state of the worker.
 */
interface WorkerState {
  readonly hmacKey: CryptoKey | undefined;
  readonly initialized: boolean;
  readonly initializing?: boolean; // guard to prevent concurrent init races
  readonly shuttingDown: boolean; // Flag for graceful shutdown
  readonly pendingCount: number;
  readonly rateLimitPerMinute: number;
  readonly developmentLogging: boolean;
  readonly windowCounts: readonly number[];
  readonly windowStart: number;
  readonly maxCanonicalLength: number;
  readonly maxConcurrentSigning: number;
  // NEW: token bucket state
  readonly tokens: number;
  readonly burst: number;
  readonly lastRefillMs: number;
  // Allowed inbound origin captured during init; undefined until set
  readonly allowedInboundOrigin?: string | undefined;
}

const createInitialState = (): WorkerState => ({
  hmacKey: undefined,
  initialized: false,
  initializing: false,
  shuttingDown: false,
  pendingCount: 0,
  rateLimitPerMinute: 0,
  developmentLogging: false,
  windowCounts: [],
  windowStart: Math.floor(Date.now() / 1000),
  maxCanonicalLength: 2_000_000,
  maxConcurrentSigning: 5,
  tokens: 0,
  burst: 0,
  lastRefillMs: Date.now(),
  allowedInboundOrigin: undefined,
});

// Maximum allowed nonce length for handshake messages to prevent resource abuse
// NOTE: Now uses getHandshakeConfig().handshakeMaxNonceLength instead of hardcoded value

/**
 * Creates a simple, encapsulated state manager using a closure.
 */
const createStateManager = (initialState: WorkerState) => {
  // eslint-disable-next-line functional/no-let -- intentional mutable state in closure for state management
  let state = initialState;
  return {
    getCurrent: (): WorkerState => state,
    update: (updates: Partial<WorkerState>) => {
      state = { ...state, ...updates };
    },
  };
};

// Keep createStateManager closure result immutable (const). The manager
// itself holds internal mutable state via closure which is intentional.
const { getCurrent, update: updateState } =
  createStateManager(createInitialState());

// Allowed inbound origin is tracked inside WorkerState (allowedInboundOrigin)

// Concurrency slot reservation now handled inline without external reservation chain

/**
 * Verifies whether a MessageEvent originates from the allowed inbound origin.
 * Returns true if the event should be accepted, false otherwise.
 */
// ...existing code... (origin handling moved into postMessage helpers)

// --- Message Handlers ---

// Attempt to reserve a concurrency slot without yielding; returns true if reserved
function tryReserveSlotInline(): boolean {
  const { pendingCount, maxConcurrentSigning } = getCurrent();
  if (pendingCount >= maxConcurrentSigning) return false;
  updateState({ pendingCount: pendingCount + 1 });
  return true;
}

/**
 * Applies handshake configuration overrides from init message.
 */
function applyHandshakeOverrides(options: InitMessage["workerOptions"]): void {
  if (
    typeof options?.handshakeMaxNonceLength === "number" ||
    Array.isArray(options?.allowedNonceFormats)
  ) {
    const current = getHandshakeConfig();
    setHandshakeConfig({
      handshakeMaxNonceLength:
        typeof options.handshakeMaxNonceLength === "number"
          ? Math.max(1, Math.floor(options.handshakeMaxNonceLength))
          : current.handshakeMaxNonceLength,
      allowedNonceFormats:
        Array.isArray(options.allowedNonceFormats) &&
        options.allowedNonceFormats.length > 0
          ? (options.allowedNonceFormats as readonly NonceFormat[])
          : current.allowedNonceFormats,
    });
  }
}

/**
 * Applies rate limiting configuration from init message.
 */
function applyRateLimitConfig(options: InitMessage["workerOptions"]): void {
  if (typeof options?.rateLimitPerMinute === "number") {
    const rateLimit = Math.max(0, Math.floor(options.rateLimitPerMinute));
    // Respect explicit burst settings even if less than the per-minute rate.
    // When unspecified, default burst to the per-minute rate.
    const burst =
      typeof options.rateLimitBurst === "number" &&
      Number.isFinite(options.rateLimitBurst)
        ? Math.max(1, Math.floor(options.rateLimitBurst))
        : rateLimit;
    updateState({
      rateLimitPerMinute: rateLimit,
      tokens: burst, // start full
      burst,
      lastRefillMs: Date.now(),
    });
  }
}

/**
 * Applies development and logging configuration from init message.
 */
function applyDevelopmentConfig(options: InitMessage["workerOptions"]): void {
  if (typeof options?.dev === "boolean") {
    updateState({ developmentLogging: options.dev });
  }
}

/**
 * Applies concurrency configuration from init message.
 */
function applyConcurrencyConfig(options: InitMessage["workerOptions"]): void {
  if (
    typeof options?.maxConcurrentSigning === "number" &&
    Number.isFinite(options.maxConcurrentSigning) &&
    options.maxConcurrentSigning > 0 &&
    options.maxConcurrentSigning <= 1000
  ) {
    updateState({
      maxConcurrentSigning: Math.floor(options.maxConcurrentSigning),
    });
  }
}

/**
 * Applies canonical length configuration from init message.
 */
function applyCanonicalConfig(options: InitMessage["workerOptions"]): void {
  if (
    typeof options?.maxCanonicalLength === "number" &&
    Number.isFinite(options.maxCanonicalLength) &&
    options.maxCanonicalLength > 0 &&
    options.maxCanonicalLength <= 10_000_000
  ) {
    updateState({
      maxCanonicalLength: Math.floor(options.maxCanonicalLength),
    });
  }
}

/**
 * Handles the initial "init" message to configure the worker and import the secret key.
 */
async function handleInitMessage(
  message: InitMessage,
  event?: MessageEvent,
): Promise<void> {
  const current = getCurrent();
  if (current.initialized || current.initializing) {
    postMessage({ type: "error", reason: "already-initialized" });
    return;
  }

  // mark as initializing to prevent concurrent init attempts
  updateState({ initializing: true });

  const options = message.workerOptions;
  if (options && typeof options === "object") {
    applyHandshakeOverrides(options);
    applyRateLimitConfig(options);
    applyDevelopmentConfig(options);
    applyConcurrencyConfig(options);
    applyCanonicalConfig(options);
  }

  if (!message.secretBuffer || !(message.secretBuffer instanceof ArrayBuffer)) {
    postMessage({ type: "error", reason: "missing-secret" });
    return;
  }

  // Establish and lock the inbound origin on first successful init.
  // If an `event` is supplied, prefer its `origin` value. This prevents
  // attackers from later posting fake control messages from other origins.
  try {
    if (typeof getCurrent().allowedInboundOrigin === "undefined") {
      const origin =
        event && typeof event.origin === "string" ? event.origin : "";
      // Default to location.origin when origin is empty (e.g. some non-browser
      // environments). We intentionally reject empty-origins unless they match
      // location.origin to avoid a permissive default.
      const locked =
        origin || (typeof location !== "undefined" ? location.origin : "");
      updateState({ allowedInboundOrigin: locked });
    }
  } catch (error) {
    // Non-fatal: don't block initialization on inability to determine origin
    // but prefer to record nothing in that case (will fall back to strict
    // runtime checks below).
    if (getCurrent().developmentLogging) {
      secureDevelopmentLog(
        "warn",
        "signing-worker",
        "failed-to-establish-allowed-origin",
        { error: sanitizeErrorForLogs(error) },
      );
    }
  }

  await importKey(message.secretBuffer);
  updateState({ initialized: true, initializing: false });
  postMessage({ type: "initialized" });
}

/**
 * Handles a handshake request to verify the worker has the correct key.
 */
async function handleHandshakeRequest(
  messageData: unknown,
  event: MessageEvent,
): Promise<void> {
  const replyPort = event?.ports?.[0] as MessagePort | undefined;
  if (!isHandshakeMessage(messageData) || !replyPort) {
    postMessage({ type: "error", reason: "invalid-handshake" });
    return;
  }

  // Validate nonce length and format using runtime-configured policies
  try {
    if (typeof messageData.nonce === "string") {
      const cfg = getHandshakeConfig();
      if (messageData.nonce.length > cfg.handshakeMaxNonceLength) {
        replyPort.postMessage({ type: "error", reason: "nonce-too-large" });
        return;
      }

      // Validate allowed formats - short-circuit on first valid format for performance
      const allowed = cfg.allowedNonceFormats;
      const isValidFormat = allowed.some((format) => {
        switch (format) {
          case "base64":
            return isLikelyBase64(messageData.nonce);
          case "base64url":
            return isLikelyBase64Url(messageData.nonce);
          case "hex":
            return /^[0-9a-f]+$/i.test(messageData.nonce);
          default:
            return false;
        }
      });

      if (!isValidFormat) {
        replyPort.postMessage({
          type: "error",
          reason: "nonce-format-invalid",
        });
        return;
      }
    }
  } catch {
    // Deliberately ignore parse/validation exceptions here and continue.
    // We don't expose internal error details to the caller.
  }

  const { hmacKey } = getCurrent();
  if (!hmacKey) {
    replyPort.postMessage({ type: "error", reason: "not-initialized" });
    return;
  }

  try {
    const nonceBytes = SHARED_ENCODER.encode(messageData.nonce);
    const sig = await crypto.subtle.sign("HMAC", hmacKey, nonceBytes);
    replyPort.postMessage({
      type: "handshake",
      signature: bytesToBase64(new Uint8Array(sig)),
    });
  } catch {
    replyPort.postMessage({ type: "error", reason: "handshake-failed" });
  }
}

/**
 * Handles a request to sign a canonical string.
 */
async function handleSignRequest(
  signMessage: SignRequest,
  event: MessageEvent,
): Promise<void> {
  const { requestId, canonical } = signMessage;
  const replyPort = event?.ports?.[0] as MessagePort | undefined;

  // Reject new requests if the worker is shutting down.
  if (getCurrent().shuttingDown) {
    const message = {
      type: "error",
      requestId,
      reason: "worker-shutting-down",
    };
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return;
  }

  if (!validateSignParameters(requestId, canonical, replyPort)) return;
  // Reserve slot synchronously to avoid races
  if (!tryReserveSlotInline()) {
    const message = {
      type: "error",
      requestId,
      reason: "worker-overloaded",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return;
  }
  // Ensure reservation state is flushed before proceeding (helps test environments)
  await Promise.resolve();
  try {
    // After reserving the slot, enforce rate-limit; if it fails, release slot
    if (!enforceRateLimit(requestId, replyPort)) return;
    await doSign(requestId, canonical, replyPort);
  } catch (signError) {
    if (getCurrent().developmentLogging) {
      secureDevelopmentLog("error", "signing-worker", "sign operation failed", {
        error: sanitizeErrorForLogs(signError),
        requestId,
      });
    }
    const message = {
      type: "error",
      requestId,
      reason: "sign-failed",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
  } finally {
    const newPendingCount = Math.max(0, getCurrent().pendingCount - 1);
    updateState({ pendingCount: newPendingCount });

    // If a shutdown has been requested and this is the last pending operation,
    // complete the shutdown process.
    if (getCurrent().shuttingDown && newPendingCount === 0) {
      postMessage({ type: "destroyed" });
      self.close();
    }
  }
}

// --- Core Logic & Validation ---

function validateSignParameters(
  requestId: unknown,
  canonical: unknown,
  replyPort?: MessagePort,
): boolean {
  if (typeof requestId !== "number" || typeof canonical !== "string") {
    const message = {
      type: "error",
      requestId: typeof requestId === "number" ? requestId : undefined,
      reason: "invalid-params",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return false;
  }
  if (canonical.length > getCurrent().maxCanonicalLength) {
    const message = {
      type: "error",
      requestId,
      reason: "canonical-too-large",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return false;
  }
  return true;
}

function enforceRateLimit(requestId: number, replyPort?: MessagePort): boolean {
  const { rateLimitPerMinute, developmentLogging } = getCurrent();
  if (rateLimitPerMinute <= 0) return true;

  // Refill tokens before attempting to consume
  refillTokens();

  const available = getCurrent().tokens;
  if (available > 0) {
    updateState({ tokens: available - 1 });
    return true;
  }

  if (developmentLogging) {
    secureDevelopmentLog("warn", "signing-worker", "rate limit exceeded", {
      availableTokens: available,
      rateLimitPerMinute,
    });
  }
  const message = {
    type: "error",
    requestId,
    reason: "rate-limit-exceeded",
  } as const;
  if (replyPort) replyPort.postMessage(message);
  else postMessage(message);
  return false;
}

// --- Token bucket helpers (millisecond precision, floor-based) ---
function refillTokens(): void {
  // Deterministic floor-based refill using ms precision.
  // We maintain tokens as integers and advance lastRefillMs by the exact
  // whole-token time added to preserve fractional accrual across calls.
  const nowMs = Date.now();
  const { rateLimitPerMinute, tokens, burst, lastRefillMs } = getCurrent();
  if (rateLimitPerMinute <= 0) return;

  const last = typeof lastRefillMs === "number" ? lastRefillMs : nowMs;
  if (nowMs <= last) return;

  // Cap the window to 1 hour to avoid extreme math and stick with floor semantics
  const deltaMs = Math.min(nowMs - last, 60 * 60 * 1000);
  if (deltaMs <= 0) return;

  // Tokens to add based on elapsed time (floor-based)
  const tokensToAdd = Math.floor((deltaMs * rateLimitPerMinute) / 60000);
  if (tokensToAdd <= 0) return; // not enough time elapsed for a whole token

  const capacityLeft = Math.max(0, burst - tokens);
  if (capacityLeft <= 0) {
    // At capacity: reset the accrual window to avoid unbounded deltas
    updateState({ lastRefillMs: nowMs });
    return;
  }

  const added = Math.min(tokensToAdd, capacityLeft);
  const perTokenMs = Math.floor(60000 / Math.max(1, rateLimitPerMinute));
  const advancedMs = added * perTokenMs;

  // If we filled to capacity, snap the clock to now; otherwise advance by the
  // exact whole-token time to preserve fractional remainder deterministically.
  const newTokens = tokens + added;
  const newLast = newTokens >= burst ? nowMs : last + advancedMs;

  updateState({ tokens: newTokens, lastRefillMs: newLast });
}

// checkOverload removed; logic is handled inline for atomic reservation

// executeSign inlined into handleSignRequest to guarantee slot reservation ordering

async function doSign(
  requestId: number,
  canonical: string,
  replyPort?: MessagePort,
) {
  const { hmacKey } = getCurrent();
  if (!hmacKey) {
    const message = {
      type: "error",
      requestId,
      reason: "not-initialized",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return;
  }

  // Let the caller handle crypto exceptions
  const data = SHARED_ENCODER.encode(canonical);
  const sig = await crypto.subtle.sign("HMAC", hmacKey, data);
  const b64 = bytesToBase64(new Uint8Array(sig));
  const message = { type: "signed", requestId, signature: b64 } as const;
  if (replyPort) replyPort.postMessage(message);
  else postMessage(message);
}

// --- Utility Functions & Type Guards ---

async function importKey(raw: ArrayBuffer): Promise<void> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"],
    );
    updateState({ hmacKey: key });
  } finally {
    // wipe secret in a best-effort manner; intentionally ignore wipe errors
    try {
      secureWipeWrapper(new Uint8Array(raw));
    } catch {
      /* best-effort only */
    }
  }
}

function isMessageWithType(data: unknown): data is { readonly type: string } {
  return (
    typeof data === "object" &&
    data !== null &&
    "type" in data &&
    typeof (data as { readonly type: unknown }).type === "string"
  );
}

function isHandshakeMessage(data: unknown): data is { readonly nonce: string } {
  return (
    typeof data === "object" &&
    data !== null &&
    "nonce" in data &&
    typeof (data as { readonly nonce: unknown }).nonce === "string"
  );
}

// Runtime guard for exposing test-only helpers
function _assertTestApiAllowedInlineWorker(): void {
  try {
    // allow in non-production or when explicit allow flag is set
    const environmentAllow =
      typeof process !== "undefined" &&
      process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true";
    const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
      "__SECURITY_KIT_ALLOW_TEST_APIS"
    ];
    // If either allow is set, permit; otherwise restrict access
    if (environmentAllow || globalAllow) return;
    throw new Error(
      "Test-only APIs are disabled. Set SECURITY_KIT_ALLOW_TEST_APIS=true to enable.",
    );
  } catch {
    throw new Error(
      "Test-only APIs are disabled. Set SECURITY_KIT_ALLOW_TEST_APIS=true to enable.",
    );
  }
}

// Export a test helper that is gated at runtime via environment flags to avoid relying on
// build-time macros in raw TS test runs. In production, calling this without explicit allow
// will throw; tests set SECURITY_KIT_ALLOW_TEST_APIS=true.
export const __test_validateHandshakeNonce:
  | ((nonce: string) => boolean)
  | undefined = (() => {
  try {
    const isTestEnvironment =
      typeof process !== "undefined" &&
      (process?.env?.["NODE_ENV"] === "test" ||
        process?.env?.["SECURITY_KIT_ALLOW_TEST_APIS"] === "true");
    const isGlobalTestFlag = !!(
      globalThis as unknown as Record<string, unknown>
    )["__SECURITY_KIT_ALLOW_TEST_APIS"];

    return isTestEnvironment || isGlobalTestFlag
      ? (nonce: string): boolean => {
          try {
            // Emit a loud warning when invoked outside strict test mode to ensure visibility
            const inStrictTest =
              typeof process !== "undefined" &&
              process?.env?.["NODE_ENV"] === "test";
            if (!inStrictTest) {
              try {
                console.warn(
                  "SECURITY WARNING: A test-only API (__test_validateHandshakeNonce) was called in a non-test environment.",
                );
              } catch {
                /* best-effort logging only */
              }
            }
            _assertTestApiAllowedInlineWorker();
            const cfg = getHandshakeConfig();
            if (typeof nonce !== "string") return false;
            if (nonce.length > cfg.handshakeMaxNonceLength) return false;

            const allowed = cfg.allowedNonceFormats;
            return allowed.some((format) => {
              switch (format) {
                case "base64":
                  return isLikelyBase64(nonce);
                case "base64url":
                  return isLikelyBase64Url(nonce);
                case "hex":
                  return /^[0-9a-f]+$/i.test(nonce);
                default:
                  return false;
              }
            });
          } catch {
            return false;
          }
        }
      : undefined;
  } catch {
    return undefined;
  }
})();

// --- Main Event Listener ---

// Use the project's centralized postMessage listener to enforce origin checks,
// sanitization, and validation. This keeps the worker consistent with the rest
// of the codebase and ensures diagnostic behavior is centralized.

// Precise runtime validator for the worker's message union. Using a function
// validator lets us express a union of different message shapes (init,
// handshake, sign, destroy) and ensures positive validation in production.
function workerMessageValidator(data: unknown): boolean {
  if (!isMessageWithType(data)) return false;
  const t = (data as { readonly type: string }).type;
  try {
    switch (t) {
      case "init": {
        // init must include a secretBuffer ArrayBuffer or ArrayBufferView and optional workerOptions
        const d = data as { readonly secretBuffer?: unknown } & Record<
          string,
          unknown
        >;
        const hasArrayBuffer =
          typeof ArrayBuffer !== "undefined" &&
          d.secretBuffer instanceof ArrayBuffer;
        const hasArrayBufferView =
          typeof ArrayBuffer !== "undefined" &&
          typeof ArrayBuffer.isView === "function" &&
          ArrayBuffer.isView(d.secretBuffer as unknown as ArrayBufferView);
        return (
          typeof d["type"] === "string" &&
          (hasArrayBuffer || hasArrayBufferView)
        );
      }
      case "handshake": {
        const d = data as { readonly nonce?: unknown } & Record<
          string,
          unknown
        >;
        return typeof d.nonce === "string" && d.nonce.length > 0;
      }
      case "sign": {
        const d = data as {
          readonly requestId?: unknown;
          readonly canonical?: unknown;
        } & Record<string, unknown>;
        return (
          typeof d.requestId === "number" && typeof d.canonical === "string"
        );
      }
      case "destroy":
        return true;
      default:
        return false;
    }
  } catch {
    return false;
  }
}

createSecurePostMessageListener({
  allowedOrigins: [typeof location !== "undefined" ? location.origin : ""],
  validate: workerMessageValidator,
  wireFormat: "structured",
  allowTypedArrays: true,
  onMessage: async (data: unknown, context) => {
    try {
      // Basic shape check
      if (!isMessageWithType(data)) {
        postMessage({ type: "error", reason: "invalid-message-format" });
        return;
      }

      // Respect established allowed origin: the central listener already
      // enforces the allowedOrigins, but we preserve worker-level locking
      // behavior by capturing the origin during init.
      const event = context?.event as MessageEvent | undefined;

      // If the worker has no locked inbound origin, allow init to set it when
      // provided via the original event context.
      const messageType = (data as { readonly type: string })["type"];
      if (messageType === "init") {
        await handleInitMessage(data as InitMessage, event);
        return;
      }

      // For other message types, enforce that the event origin matches the
      // stored allowed origin or fallback policies.
      if (
        event &&
        !isEventAllowedWithLock(event, getCurrent().allowedInboundOrigin)
      ) {
        if (getCurrent().developmentLogging) {
          secureDevelopmentLog(
            "warn",
            "signing-worker",
            "rejected-message-origin",
            {
              origin: event?.origin ?? undefined,
              ports: (event?.ports || []).length,
            },
          );
        }
        return;
      }

      const messageData = data as { readonly type: string } & Record<
        string,
        unknown
      >;
      switch (messageData.type) {
        case "handshake":
          // prefer the original MessageEvent for reply ports
          await handleHandshakeRequest(messageData, event as MessageEvent);
          break;
        case "sign":
          await handleSignRequest(
            messageData as SignRequest,
            event as MessageEvent,
          );
          break;
        case "destroy":
          updateState({ shuttingDown: true });
          if (getCurrent().pendingCount === 0) {
            postMessage({ type: "destroyed" });
            self.close();
          }
          break;
        default:
          postMessage({
            type: "error",
            requestId: undefined,
            reason: "unknown-message-type",
          });
      }
    } catch (error) {
      postMessage({
        type: "error",
        requestId: undefined,
        reason: "worker-exception",
      });
      if (getCurrent().developmentLogging) {
        secureDevelopmentLog(
          "error",
          "signing-worker",
          "Unhandled exception in worker event listener",
          {
            error: sanitizeErrorForLogs(error),
          },
        );
      }
    }
  },
});
