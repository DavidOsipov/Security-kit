// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// Module-style worker for performing HMAC signing in a separate thread.

import { SHARED_ENCODER } from "../encoding";
import type { InitMessage, SignRequest } from "../protocol";
import { bytesToBase64, secureWipeWrapper } from "../encoding-utils";
import { secureDevLog } from "../utils";
import { sanitizeErrorForLogs } from "../errors";

// --- State Management ---

/**
 * Defines the complete, immutable state of the worker.
 */
interface WorkerState {
  readonly hmacKey: CryptoKey | undefined;
  readonly initialized: boolean;
  readonly shuttingDown: boolean; // Flag for graceful shutdown
  readonly pendingCount: number;
  readonly rateLimitPerMinute: number;
  readonly developmentLogging: boolean;
  readonly windowCounts: readonly number[];
  readonly windowStart: number;
  readonly maxCanonicalLength: number;
  readonly maxConcurrentSigning: number;
}

const createInitialState = (): WorkerState => ({
  hmacKey: undefined,
  initialized: false,
  shuttingDown: false,
  pendingCount: 0,
  rateLimitPerMinute: 0,
  developmentLogging: false,
  windowCounts: [],
  windowStart: Math.floor(Date.now() / 1000),
  maxCanonicalLength: 2_000_000,
  maxConcurrentSigning: 5,
});

/**
 * Creates a simple, encapsulated state manager using a closure.
 */
const createStateManager = (initialState: WorkerState) => {
  let state = initialState;
  return {
    getCurrent: (): WorkerState => state,
    update: (updates: Partial<WorkerState>) => {
      state = { ...state, ...updates };
    },
  };
};

const { getCurrent, update: updateState } =
  createStateManager(createInitialState());

// --- Message Handlers ---

/**
 * Handles the initial "init" message to configure the worker and import the secret key.
 */
async function handleInitMessage(message: InitMessage): Promise<void> {
  if (getCurrent().initialized) {
    postMessage({ type: "error", reason: "already-initialized" });
    return;
  }

  const options = message.workerOptions;
  if (options && typeof options === "object") {
    if (typeof options.rateLimitPerMinute === "number") {
      updateState({
        rateLimitPerMinute: Math.max(0, Math.floor(options.rateLimitPerMinute)),
      });
    }
    if (typeof options.dev === "boolean") {
      updateState({ developmentLogging: options.dev });
    }
    if (
      typeof options.maxConcurrentSigning === "number" &&
      Number.isFinite(options.maxConcurrentSigning) &&
      options.maxConcurrentSigning > 0 &&
      options.maxConcurrentSigning <= 1000
    ) {
      updateState({
        maxConcurrentSigning: Math.floor(options.maxConcurrentSigning),
      });
    }
    if (
      typeof options.maxCanonicalLength === "number" &&
      Number.isFinite(options.maxCanonicalLength) &&
      options.maxCanonicalLength > 0 &&
      options.maxCanonicalLength <= 10_000_000
    ) {
      updateState({
        maxCanonicalLength: Math.floor(options.maxCanonicalLength),
      });
    }
  }

  if (!message.secretBuffer || !(message.secretBuffer instanceof ArrayBuffer)) {
    postMessage({ type: "error", reason: "missing-secret" });
    return;
  }

  await importKey(message.secretBuffer);
  updateState({ initialized: true });
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
  if (!enforceRateLimit(requestId, replyPort)) return;
  if (checkOverload(requestId, replyPort)) return;

  await executeSign(requestId, canonical, replyPort);
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
  const { rateLimitPerMinute, windowCounts, windowStart, developmentLogging } =
    getCurrent();
  if (rateLimitPerMinute <= 0) return true;

  const nowSec = Math.floor(Date.now() / 1000);
  const advanced = advanceWindow(windowCounts, windowStart, nowSec);
  const total = totalWindow(advanced.counts);

  if (total >= rateLimitPerMinute) {
    if (developmentLogging) {
      secureDevLog("warn", "signing-worker", "rate limit exceeded", {
        total,
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

  const head = (advanced.counts[0] ?? 0) + 1;
  const rest = advanced.counts.slice(1);
  const newCounts = [head, ...rest] as readonly number[];

  updateState({ windowCounts: newCounts, windowStart: advanced.start });
  return true;
}

function checkOverload(requestId: number, replyPort?: MessagePort): boolean {
  const { pendingCount, maxConcurrentSigning, developmentLogging } =
    getCurrent();
  if (pendingCount >= maxConcurrentSigning) {
    if (developmentLogging) {
      secureDevLog("warn", "signing-worker", "worker overloaded", {
        pendingCount,
        maxConcurrentSigning,
      });
    }
    const message = { type: "error", requestId, reason: "worker-overloaded" };
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return true;
  }
  return false;
}

async function executeSign(
  requestId: number,
  canonical: string,
  replyPort?: MessagePort,
): Promise<void> {
  updateState({ pendingCount: getCurrent().pendingCount + 1 });
  try {
    await doSign(requestId, canonical, replyPort);
  } catch (signError) {
    if (getCurrent().developmentLogging) {
      secureDevLog("error", "signing-worker", "sign operation failed", {
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
    try {
      secureWipeWrapper(new Uint8Array(raw));
    } catch {
      // best-effort only
    }
  }
}

function advanceWindow(
  currentCounts: readonly number[],
  oldStart: number,
  nowSec: number,
): { readonly counts: readonly number[]; readonly start: number } {
  const elapsed = Math.max(0, nowSec - oldStart);
  if (elapsed === 0) return { counts: currentCounts, start: oldStart };
  const capped = Math.min(elapsed, 60);
  const zeros = Array.from({ length: capped }, () => 0);
  const newCounts = [...zeros, ...currentCounts];
  return { counts: newCounts.slice(0, 60), start: nowSec };
}

function totalWindow(counts: readonly number[]): number {
  return counts.reduce((a, b) => a + b, 0);
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

// --- Main Event Listener ---

self.addEventListener("message", async (event: MessageEvent) => {
  if (event.data === undefined || typeof event.data !== "object") {
    postMessage({ type: "error", reason: "invalid-message-format" });
    return;
  }

  try {
    if (!isMessageWithType(event.data)) {
      postMessage({ type: "error", reason: "invalid-message-format" });
      return;
    }

    const messageData = event.data;

    switch (messageData.type) {
      case "init":
        await handleInitMessage(messageData as InitMessage);
        break;
      case "handshake":
        await handleHandshakeRequest(messageData, event);
        break;
      case "sign":
        await handleSignRequest(messageData as SignRequest, event);
        break;
      case "destroy":
        updateState({ shuttingDown: true });
        // If no operations are pending, we can close immediately.
        if (getCurrent().pendingCount === 0) {
          postMessage({ type: "destroyed" });
          self.close();
        }
        // Otherwise, the last running `executeSign` will handle the shutdown.
        break;
      default:
        postMessage({
          type: "error",
          requestId: undefined,
          reason: "unknown-message-type",
        });
    }
  } catch (e) {
    postMessage({
      type: "error",
      requestId: undefined,
      reason: "worker-exception",
    });
    if (getCurrent().developmentLogging) {
      secureDevLog(
        "error",
        "signing-worker",
        "Unhandled exception in worker event listener",
        { error: sanitizeErrorForLogs(e) },
      );
    }
  }
});
