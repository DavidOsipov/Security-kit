// SPDX-License-Identifier: MIT
// Shared protocol types between the main thread signer and the worker.

/** Init message sent from main thread to worker (transfer ArrayBuffer) */
export type InitMessage = {
  readonly type: "init";
  readonly secretBuffer: ArrayBuffer;
  readonly workerOptions?: {
    readonly rateLimitPerMinute?: number;
    readonly dev?: boolean;
    /** Optional: cap concurrent signing operations inside worker */
    readonly maxConcurrentSigning?: number;
    /** Optional: maximum allowed canonical string length */
    readonly maxCanonicalLength?: number;
  };
  readonly kid?: string;
};

export type InitAck = { readonly type: "initialized" };
export type DestroyedMessage = { readonly type: "destroyed" };

export type SignRequest = {
  readonly type: "sign";
  readonly requestId: number;
  readonly canonical: string;
};

export type DestroyRequest = { readonly type: "destroy" };

export type SignedResponse = {
  readonly type: "signed";
  readonly requestId: number;
  readonly signature: string;
};

export type ErrorReason =
  | "invalid-handshake"
  | "not-initialized"
  | "handshake-failed"
  | "invalid-params"
  | "canonical-too-large"
  | "rate-limit-exceeded"
  | "worker-overloaded"
  | "missing-secret"
  | "sign-failed"
  | "invalid-message-format"
  | "unknown-message-type"
  | "worker-exception";

export type ErrorResponse = {
  readonly type: "error";
  readonly requestId?: number | null;
  readonly reason?: ErrorReason;
};

export type WorkerMessage =
  | InitMessage
  | InitAck
  | SignRequest
  | SignedResponse
  | ErrorResponse
  | DestroyRequest
  | DestroyedMessage
  | { readonly type?: unknown };
