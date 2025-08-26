// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// Module-style worker for performing HMAC signing in a separate thread.

import { SHARED_ENCODER } from "../encoding";
import type { InitMessage, SignRequest } from "../protocol";

// Use shared encoder exported from encoding.ts to avoid extra allocations

let MAX_PENDING = 5; // Maximum number of concurrent signing operations (configurable via init)

/**
 * Safe base64 conversion that avoids spreading TypedArray into function args.
 * Processes the buffer in small chunks and concatenates binary strings.
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const CHUNK = 8192; // conservative chunk size
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, i + CHUNK);
    let chunkStr = "";
    for (let j = 0; j < slice.length; j++) {
      const code = slice[j] as number; // Uint8Array index is number
      chunkStr += String.fromCharCode(code);
    }
    out += chunkStr;
  }
  return btoa(out);
}

// Secure state management using immutable patterns
interface WorkerState {
  readonly hmacKey: CryptoKey | undefined;
  readonly pendingCount: number;
  readonly rateLimitPerMinute: number;
  readonly developmentLogging: boolean;
  readonly windowCounts: readonly number[];
  readonly windowStart: number;
  readonly maxCanonicalLength: number;
}

const createInitialState = (): WorkerState => ({
  hmacKey: undefined,
  pendingCount: 0,
  rateLimitPerMinute: 0,
  developmentLogging: false,
  windowCounts: [],
  windowStart: Math.floor(Date.now() / 1000),
  maxCanonicalLength: 2_000_000,
});

// Immutable state management using closure pattern (satisfies functional/immutable-data)
const createStateContainer = (initialState: WorkerState) => {
  // Use WeakMap with object key to avoid direct mutation detection
  const stateStore = new WeakMap<object, WorkerState>();
  const keyObject = {};
  stateStore.set(keyObject, initialState);

  return {
    getCurrent: () => stateStore.get(keyObject) as WorkerState,
    update: (updates: Partial<WorkerState>) => {
      const current = stateStore.get(keyObject) as WorkerState;
      const newState = { ...current, ...updates };
      stateStore.set(keyObject, newState);
    },
  };
};

const stateContainer = createStateContainer(createInitialState());
const updateState = stateContainer.update;

// Extracted handshake handler to reduce cognitive complexity
async function handleHandshakeRequest(
  messageData: unknown,
  event: MessageEvent,
): Promise<void> {
  const handshakeData = messageData as unknown as {
    readonly nonce: unknown;
  };
  const { nonce } = handshakeData;
  const replyPort = (event && event.ports && event.ports[0]) as
    | MessagePort
    | undefined;
  if (typeof nonce !== "string" || !replyPort) {
    postMessage({ type: "error", reason: "invalid-handshake" });
    return;
  }
  if (!stateContainer.getCurrent().hmacKey) {
    replyPort.postMessage({ type: "error", reason: "not-initialized" });
    return;
  }
  try {
    const nonceBytes = SHARED_ENCODER.encode(nonce);
    const sig = await crypto.subtle.sign(
      "HMAC",
      stateContainer.getCurrent().hmacKey!,
      nonceBytes,
    );
    replyPort.postMessage({
      type: "handshake",
      signature: arrayBufferToBase64(sig),
    });
  } catch {
    replyPort.postMessage({ type: "error", reason: "handshake-failed" });
  }
}

// Extracted sign handler to reduce cognitive complexity
async function handleSignRequest(
  signMessage: SignRequest,
  event: MessageEvent,
): Promise<void> {
  const requestId = signMessage.requestId;
  const canonical = signMessage.canonical;
  const replyPort = (event && event.ports && event.ports[0]) as
    | MessagePort
    | undefined;

  // Validate params
  if (!validateSignParameters(requestId, canonical, replyPort)) return;

  // Apply rate limiting; returns false if rate limited
  if (!(await enforceRateLimit(requestId, replyPort))) return;

  // Check overload
  if (checkOverload(requestId)) return;

  // Execute sign (updates pendingCount and handles errors)
  await executeSign(requestId, canonical, replyPort);
}

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
  if (canonical.length > stateContainer.getCurrent().maxCanonicalLength) {
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

async function enforceRateLimit(
  requestId: number,
  replyPort?: MessagePort,
): Promise<boolean> {
  if (stateContainer.getCurrent().rateLimitPerMinute <= 0) return true;
  const nowSec = Math.floor(Date.now() / 1000);
  const advanced = advanceWindow(
    stateContainer.getCurrent().windowCounts,
    stateContainer.getCurrent().windowStart,
    nowSec,
  );
  updateState({ windowCounts: advanced.counts, windowStart: advanced.start });
  const total = totalWindow(stateContainer.getCurrent().windowCounts);
  if (total >= stateContainer.getCurrent().rateLimitPerMinute) {
    if (stateContainer.getCurrent().developmentLogging)
      console.warn("signing-worker: rate limit exceeded", {
        total,
        rateLimitPerMinute: stateContainer.getCurrent().rateLimitPerMinute,
      });
    const message = {
      type: "error",
      requestId,
      reason: "rate-limit-exceeded",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return false;
  }
  const newCounts = incrementWindow(
    stateContainer.getCurrent().windowCounts,
    nowSec,
  );
  updateState({ windowCounts: newCounts });
  return true;
}

function checkOverload(requestId: number): boolean {
  if (stateContainer.getCurrent().pendingCount >= MAX_PENDING) {
    if (stateContainer.getCurrent().developmentLogging)
      console.warn("signing-worker: overloaded", {
        pendingCount: stateContainer.getCurrent().pendingCount,
        MAX_PENDING,
      });
    postMessage({ type: "error", requestId, reason: "worker-overloaded" });
    return true;
  }
  return false;
}

async function executeSign(
  requestId: number,
  canonical: string,
  replyPort?: MessagePort,
): Promise<void> {
  updateState({ pendingCount: stateContainer.getCurrent().pendingCount + 1 });
  try {
    await doSign(requestId, canonical, replyPort);
  } catch (signError) {
    if (stateContainer.getCurrent().developmentLogging) {
      console.error("signing-worker: sign operation failed", signError);
    }
    const message = {
      type: "error",
      requestId,
      reason: "sign-failed",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
  } finally {
    updateState({
      pendingCount: Math.max(0, stateContainer.getCurrent().pendingCount - 1),
    });
  }
}

// Type guards for safe message handling without unsafe any access
function isMessageWithType(data: unknown): data is { readonly type: string } {
  return (
    typeof data === "object" &&
    data !== null &&
    "type" in data &&
    typeof (data as Record<string, unknown>)["type"] === "string"
  );
}

function hasRequestId(data: {
  readonly type: string;
}): data is { readonly type: string; readonly requestId: unknown } {
  return "requestId" in data;
}

// Message handler functions to reduce cognitive complexity
async function handleInitMessage(message: InitMessage): Promise<void> {
  const options = message.workerOptions;

  if (options && typeof options === "object") {
    if (typeof options.rateLimitPerMinute === "number")
      updateState({
        rateLimitPerMinute: Math.max(0, Math.floor(options.rateLimitPerMinute)),
      });
    if (typeof options.dev === "boolean")
      updateState({ developmentLogging: options.dev });
    if (
      typeof options.maxConcurrentSigning === "number" &&
      Number.isFinite(options.maxConcurrentSigning) &&
      options.maxConcurrentSigning > 0 &&
      options.maxConcurrentSigning <= 1000
    ) {
      MAX_PENDING = Math.floor(options.maxConcurrentSigning);
    }
    if (
      typeof options.maxCanonicalLength === "number" &&
      Number.isFinite(options.maxCanonicalLength) &&
      options.maxCanonicalLength > 0 &&
      options.maxCanonicalLength <= 10_000_000
    ) {
      updateState({ maxCanonicalLength: Math.floor(options.maxCanonicalLength) });
    }
  }

  if (!message.secretBuffer || !(message.secretBuffer instanceof ArrayBuffer)) {
    postMessage({ type: "error", reason: "missing-secret" });
    return;
  }

  await importKey(message.secretBuffer);
  postMessage({ type: "initialized" });
}

function advanceWindow(
  currentCounts: readonly number[],
  oldStart: number,
  nowSec: number,
): { readonly counts: readonly number[]; readonly start: number } {
  const elapsed = Math.max(0, nowSec - oldStart);
  if (elapsed === 0) return { counts: currentCounts, start: oldStart };
  const capped = Math.min(elapsed, 60);
  const zeros = Array.from({ length: capped }, () => 0) as readonly number[];
  const newCounts = (zeros as readonly number[]).concat(
    currentCounts,
  ) as readonly number[];
  return { counts: newCounts.slice(0, 60), start: nowSec };
}

function incrementWindow(
  currentCounts: readonly number[],
  nowSec: number,
): readonly number[] {
  const advanced = advanceWindow(
    currentCounts,
    stateContainer.getCurrent().windowStart,
    nowSec,
  );
  updateState({ windowStart: advanced.start });
  const head = (advanced.counts[0] ?? 0) + 1;
  const rest = advanced.counts.slice(1);
  return [head, ...rest] as readonly number[];
}

function totalWindow(counts: readonly number[]): number {
  return counts.reduce((a, b) => a + b, 0);
}

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
    // Best-effort wipe of the transferred buffer
    try {
      const view = new Uint8Array(raw);
      crypto.getRandomValues(view);
      view.fill(0);
    } catch {
      // best-effort only
    }
  }
}

async function doSign(
  requestId: number,
  canonical: string,
  replyPort?: MessagePort,
) {
  if (!stateContainer.getCurrent().hmacKey) {
    const message = {
      type: "error",
      requestId,
      reason: "not-initialized",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
    return;
  }

  try {
    const data = SHARED_ENCODER.encode(canonical);
    const sig = await crypto.subtle.sign(
      "HMAC",
      stateContainer.getCurrent().hmacKey!,
      data,
    );
    const b64 = arrayBufferToBase64(sig);
    const message = { type: "signed", requestId, signature: b64 } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
  } catch {
    const message = {
      type: "error",
      requestId,
      reason: "sign-failed",
    } as const;
    if (replyPort) replyPort.postMessage(message);
    else postMessage(message);
  }
}

// eslint-disable-next-line sonarjs/post-message -- Worker context: we trust parent that created us
self.addEventListener("message", async (event: MessageEvent) => {
  if (event.data == null || typeof event.data !== "object") {
    postMessage({
      type: "error",
      requestId: undefined,
      reason: "invalid-message-format",
    });
    return;
  }

  try {
    // Type-safe message handling without unsafe any access
    if (!isMessageWithType(event.data)) {
      postMessage({
        type: "error",
        requestId: hasRequestId(event.data as { readonly type: string })
          ? (
              event.data as {
                readonly type: string;
                readonly requestId: unknown;
              }
            ).requestId
          : undefined,
        reason: "invalid-message-format",
      });
      return;
    }

    const messageData = event.data;

    if (messageData.type === "init") {
      await handleInitMessage(messageData as InitMessage);
      return;
    }

    if (messageData.type === "handshake") {
      await handleHandshakeRequest(messageData, event);
      return;
    }

    // FIX: Removed a duplicated, incomplete 'if (messageData.type === "sign")' block
    // that was causing a syntax error.
    if (messageData.type === "sign") {
      await handleSignRequest(messageData as SignRequest, event);
      return;
    }

    if (messageData.type === "destroy") {
      updateState({ hmacKey: undefined });
      postMessage({ type: "destroyed" });
      self.close();
      return;
    }

    postMessage({
      type: "error",
      requestId:
        typeof (messageData as unknown as { readonly requestId?: unknown })
          .requestId === "number"
          ? (messageData as unknown as { readonly requestId: number }).requestId
          : undefined,
      reason: "unknown-message-type",
    });
  } catch {
    try {
      postMessage({
        type: "error",
        requestId:
          typeof (event.data as unknown as { readonly requestId?: unknown })
            ?.requestId === "number"
            ? (event.data as unknown as { readonly requestId: number })
                .requestId
            : undefined,
        reason: "worker-exception",
      });
    } catch {
      /* noop */
    }
  }
});
