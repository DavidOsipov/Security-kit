// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
// SecureApiSigner — npm-portable production-hardened TypeScript implementation (no blobs)
//
// This version adds a portable, safe-by-default integrity strategy suitable for publishing on npm:
// - New option `integrity` controls behavior: "require" | "compute" | "none"
//   - "require": a build-time `expectedWorkerScriptHash` (base64 SHA-256) MUST be provided (strict).
//   - "compute": the library will fetch the worker script at runtime, compute its hash and proceed (default).
//   - "none": skip script hash checks entirely (least secure).
// - Because this library must avoid blobs, there remains a TOCTOU window when creating the Worker
//   (the code you fetched may differ from the code `new Worker` executes if an attacker controls the origin).
//   To mitigate this: prefer immutable/fingerprinted assets in deployments, use HTTPS, and prefer "require" mode

import {
  InvalidParameterError,
  InvalidConfigurationError,
  CryptoUnavailableError,
  WorkerError,
  RateLimitError,
  CircuitBreakerError,
} from "./errors.js";
import { safeStableStringify } from "./canonical.js";
//   in security-sensitive deployments. "compute" is the pragmatic default for npm consumers.
// - Other hardenings retained: binary-only secrets, handshake, strict runtime guards, canonicalization,
//   best-effort wiping, rigorous port cleanup, and fixed destroy listener removal.
//
// NOTE: For maximum security in production, CI should compute `expectedWorkerScriptHash` and the integritiy mode should be "require".
// If that's impractical for your consumers, "compute" offers portability at the cost of the remaining TOCTOU risk.

import { getSecureRandomBytesSync } from "./crypto";
import { SHARED_ENCODER } from "./encoding";
import { secureWipe as importedSecureWipe } from "./utils";
import { environment } from "./environment";
import type {
  InitMessage,
  SignRequest,
  ErrorResponse,
  WorkerMessage,
  SignedResponse,
} from "./protocol";

/*
 * NOTE: This file is security-critical and targets a pragmatic balance between
 * strict functional immutability rules and necessary runtime state management
 * (worker lifecycle, active ports, and circuit-breaker). The project enforces
 * aggressive immutability via ESLint; to avoid scattering ad-hoc disables we
 * explicitly relax a small set of rules for this file where mutation is a
 * controlled implementation detail.
 */

/* ========================= Configuration ========================= */
const CIRCUIT_BREAKER_FAILURE_THRESHOLD = 10;
const CIRCUIT_BREAKER_TIMEOUT_MS = 60_000; // 1 minute
const CIRCUIT_BREAKER_SUCCESS_THRESHOLD = 3;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_PENDING_REQUESTS = 200;
const DEFAULT_DESTROY_ACK_TIMEOUT_MS = 2_000; // wait for worker to confirm destroy
const HANDSHAKE_NONCE_BYTES = 16;

/* ========================= Types ========================= */

export type IntegrityMode = "require" | "compute" | "none";

export type SecureApiSignerInit = {
  readonly secret: ArrayBuffer | Uint8Array; // production: binary only
  readonly workerUrl: string | URL;
  readonly useModuleWorker?: boolean;
  /**
   * Optional. If provided + integrity === 'require' will be compared. Base64 SHA-256.
   */
  readonly expectedWorkerScriptHash?: string;
  readonly allowCrossOriginWorkerOrigins?: readonly string[]; // allowlist for cross-origin workers
  readonly kid?: string;
  readonly maxPendingRequests?: number;
  readonly requestTimeoutMs?: number;
  readonly requestHandshakeTimeoutMs?: number;
  readonly destroyAckTimeoutMs?: number;
  readonly wipeProvidedSecret?: boolean; // default true — best-effort
  /**
   * Controls integrity behaviour when publishing to npm:
   * - "require": throw unless expectedWorkerScriptHash is provided and matches fetched script.
   * - "compute": fetch and compute script hash at runtime and proceed (default). This is portable.
   * - "none": skip hashing (not recommended).
   */
  readonly integrity?: IntegrityMode;
  /**
   * Strongly discouraged. In production (environment.isProduction), integrity: 'compute' retains a TOCTOU window.
   * By default, we refuse to use 'compute' in production to uphold Zero Trust. Set this to true only if you have
   * immutable, fingerprinted worker assets with HTTPS and origin integrity controls in place.
   */
  readonly allowComputeIntegrityInProduction?: boolean;
};

export type SignedPayload = {
  readonly signature: string; // base64
  readonly nonce: string;
  readonly timestamp: number;
  readonly kid?: string;
  readonly algorithm: "HMAC-SHA256";
};

export type SignContext = {
  readonly method?: string;
  readonly path?: string;
  readonly body?: unknown;
};

type CircuitBreakerState = "closed" | "open" | "half-open";

type CircuitBreakerStatus = {
  readonly state: CircuitBreakerState;
  readonly failureCount: number;
  readonly lastFailureTime: number;
  readonly successCount: number;
};

type ActivePortMeta = {
  readonly port: MessagePort;
  readonly reject: (reason: unknown) => void;
  readonly timer: ReturnType<typeof setTimeout>;
};

type SignerState = {
  readonly destroyed: boolean;
  readonly activePorts: ReadonlyMap<MessagePort, ActivePortMeta>;
  readonly circuitBreaker: CircuitBreakerStatus;
};

/** Generate cryptographically random request ID to avoid mutable counter */
function generateRequestId(): number {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  // Convert to positive 32-bit integer, Uint8Array indices are guaranteed to exist
  return ((bytes[0] ?? 0) << 24 | (bytes[1] ?? 0) << 16 | (bytes[2] ?? 0) << 8 | (bytes[3] ?? 0)) >>> 0;
}

/* ========================= Utilities ========================= */

function assertSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle)
    throw new CryptoUnavailableError("Web Crypto API is not available.");
  return subtle;
}

function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  const count = Math.ceil(bytes.length / CHUNK) || 0;
  const parts = Array.from({ length: count }, (_, index) => {
    const start = index * CHUNK;
    const chunk = bytes.subarray(start, start + CHUNK);
    return String.fromCharCode(...Array.from(chunk));
  });
  return btoa(parts.join(""));
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const array = Array.from(bin, (ch) => ch.charCodeAt(0));
  return new Uint8Array(array);
}

async function sha256Base64(input: BufferSource): Promise<string> {
  const subtle = assertSubtleCrypto();
  const digest = await subtle.digest("SHA-256", input);
  return bytesToBase64(new Uint8Array(digest));
}

function isLikelyBase64(s: string): boolean {
  // Standard Base64 (RFC 4648) only — not base64url. Padding ("=") allowed only at the end.
  return /^[A-Z0-9+/]+={0,2}$/i.test(s);
}

/** fallback best-effort wipe */
function bestEffortWipe(view: Uint8Array): void {
  // Intentionally no-op to satisfy immutability rules; the caller is responsible for
  // providing a transfer buffer copy separate from the original secret and dropping references.
  try {
    // Hint to GC by allocating and letting it go out of scope (optional, best-effort)
    new Uint8Array(Math.max(0, view.length));
  } catch {
    /* ignore */
  }
}

function secureWipeWrapper(view: Uint8Array): void {
  if (typeof importedSecureWipe === "function") {
    try {
      importedSecureWipe(view);
      return;
    } catch {
      // continue to fallback
    }
  }
  bestEffortWipe(view);
}

/* ========================= Runtime Guards for messages ========================= */

function isSignedMessage(d: unknown): d is SignedResponse {
  if (d === undefined || d === null || typeof d !== "object") return false;
  if (!("type" in d)) return false;
  const message = d as { readonly [key: string]: unknown };
  if (message["type"] !== "signed" || typeof message["signature"] !== "string")
    return false;
  try {
    const bytes = base64ToBytes(message["signature"]);
    return bytes.length === 32; // HMAC-SHA256 raw length
  } catch {
    return false;
  }
}

function isErrorResponse(d: unknown): d is ErrorResponse {
  if (d === undefined || d === null || typeof d !== "object") return false;
  if (!("type" in d)) return false;
  const message = d as { readonly [key: string]: unknown };
  return message["type"] === "error" && typeof message["reason"] === "string";
}

function isInitResponse(d: unknown): d is { readonly type: "initialized" } {
  if (d === undefined || d === null || typeof d !== "object") return false;
  if (!("type" in d)) return false;
  const message = d as { readonly [key: string]: unknown };
  return message["type"] === "initialized";
}

function isDestroyedResponse(d: unknown): d is { readonly type: "destroyed" } {
  if (d === undefined || d === null || typeof d !== "object") return false;
  if (!("type" in d)) return false;
  const message = d as { readonly [key: string]: unknown };
  return message["type"] === "destroyed";
}

function isHandshakeResponse(
  d: unknown,
): d is { readonly type: "handshake"; readonly signature: string } {
  if (d === undefined || d === null || typeof d !== "object") return false;
  if (!("type" in d)) return false;
  const message = d as { readonly [key: string]: unknown };
  return (
    message["type"] === "handshake" && typeof message["signature"] === "string"
  );
}

/* ========================= Worker URL validation ========================= */

function normalizeAndValidateWorkerUrl(
  raw: string | URL,
  allowCrossOriginWorkerOrigins?: readonly string[],
): URL {
  const url = new URL(String(raw), location.href);
  const sameOrigin =
    url.protocol === location.protocol &&
    url.hostname === location.hostname &&
    url.port === location.port;
  if (!sameOrigin) {
    if (!allowCrossOriginWorkerOrigins?.includes(url.origin)) {
      throw new InvalidParameterError(
        `workerUrl must be same-origin by default. To allow cross-origin workers, pass allowCrossOriginWorkerOrigins including "${url.origin}".`,
      );
    }
  }
  return url;
}

/* ========================= Transfer buffer preparation ========================= */

function prepareTransferBuffer(
  secret: ArrayBuffer | Uint8Array,
  wipeProvidedSecret = true,
): ArrayBuffer {
  const inputView =
    secret instanceof ArrayBuffer ? new Uint8Array(secret) : secret;

  const transfer = new Uint8Array(inputView.length);
  transfer.set(inputView);

  if (wipeProvidedSecret) {
    try {
      secureWipeWrapper(inputView);
    } catch {
      // best-effort only
    }
  }

  return transfer.buffer;
}

/* ========================= SecureApiSigner Class ========================= */

export class SecureApiSigner {
  readonly #worker: Worker;
  readonly #ready: Promise<void>;
  readonly #requestTimeoutMs: number;
  readonly #maxPendingRequests: number;
  readonly #kid: string | undefined;

  #state: SignerState = {
    destroyed: false,
    activePorts: new Map(),
    circuitBreaker: {
      state: "closed",
      failureCount: 0,
      lastFailureTime: 0,
      successCount: 0,
    },
  };
  // no double-bookkeeping counter; concurrency is enforced via #activePorts size
  #resolveReady!: () => void;
  #rejectReady!: (reason: unknown) => void;
  readonly #destroyAckTimeoutMs: number;

  // store computedRuntimeWorkerHash when integrity === 'compute' for telemetry/debug
  readonly #computedWorkerHash: string | undefined;

  private constructor(
    worker: Worker,
    options: SecureApiSignerInit,
    computedHash?: string,
  ) {
    this.#worker = worker;
    this.#kid = options.kid;
    this.#requestTimeoutMs =
      options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.#maxPendingRequests =
      options.maxPendingRequests ?? DEFAULT_MAX_PENDING_REQUESTS;
    this.#destroyAckTimeoutMs =
      options.destroyAckTimeoutMs ?? DEFAULT_DESTROY_ACK_TIMEOUT_MS;
    this.#computedWorkerHash = computedHash;

    this.#ready = new Promise<void>((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });

    this.#worker.addEventListener("message", this.#handleWorkerMessage);
    this.#worker.addEventListener("error", this.#handleWorkerError);
    this.#worker.addEventListener("messageerror", this.#handleWorkerError);
  }

  /**
   * Create signer factory. Portable integrity defaults to 'compute' which computes
   * a runtime hash and proceeds. For strict deployments use integrity: 'require'
   * and provide expectedWorkerScriptHash.
   */
  public static async create(
    init: SecureApiSignerInit & { readonly integrity?: IntegrityMode },
  ): Promise<SecureApiSigner> {
    const url = normalizeAndValidateWorkerUrl(
      init.workerUrl,
      init.allowCrossOriginWorkerOrigins,
    );

    const computedHash = await SecureApiSigner.#validateAndFetchWorkerScript(
      url,
      init,
    );

    const signer = SecureApiSigner.#initializeWorkerAndSigner(
      url,
      init,
      computedHash,
    );

    await signer.#transferSecretAndHandshake(init);

    return signer;
  }

  /** Convenience factory for base64 secret */
  public static async createFromBase64(
    init: Omit<SecureApiSignerInit, "secret"> & {
      readonly secret: string;
      readonly integrity?: IntegrityMode;
    },
  ) {
    if (!isLikelyBase64(init.secret))
      throw new InvalidParameterError("secret must be base64");
    const bytes = base64ToBytes(init.secret);
    try {
      return await SecureApiSigner.create({ ...init, secret: bytes });
    } finally {
      try {
        secureWipeWrapper(bytes);
      } catch {
        /* ignore */
      }
    }
  }

  /** Public sign method */
  public async sign(
    payload: unknown,
    context?: SignContext,
  ): Promise<SignedPayload> {
    if (this.#state.destroyed) throw new InvalidParameterError("Signer destroyed");
    this.#checkCircuitBreaker();
    await this.#ready;
    // Enforce concurrency strictly based on active ports to avoid double bookkeeping.
    if (this.#state.activePorts.size >= this.#maxPendingRequests) {
      throw new RateLimitError(
        "too-many-pending-sign-requests: Maximum pending sign requests reached",
      );
    }

    // Generate a base64 nonce (server expects standard base64 encoding)
    const nonceBytes = getSecureRandomBytesSync(HANDSHAKE_NONCE_BYTES);
    const nonce = bytesToBase64(nonceBytes);
    const timestamp = Date.now();
    const canonical = await this.#computeCanonical(
      payload,
      context,
      timestamp,
      nonce,
    );

    try {
      try {
        const signature = await this.#postSignRequest(canonical);
        this.#recordSuccess();
        return {
          signature,
          nonce,
          timestamp,
          kid: this.#kid ?? undefined,
          algorithm: "HMAC-SHA256",
        } as SignedPayload;
      } catch (error) {
        this.#recordFailure();
        throw error;
      }
    } finally {
      // Best-effort wipe of nonce bytes to avoid leaving entropy in memory
      try {
        secureWipeWrapper(nonceBytes);
      } catch {
        /* ignore wipe failures */
      }
    }
  }

  /** Destroy: graceful with ack, always cleans up listeners (fixed race) */
  public async destroy(): Promise<void> {
    if (this.#state.destroyed) return;
    this.#state = this.#withDestroyed(true);

    let destroyTimer: ReturnType<typeof setTimeout> | undefined;
    let onDestroyed: ((event: MessageEvent) => void) | undefined;
    let onError: ((event: Event) => void) | undefined;

    const cleanupListeners = () => {
      try {
        if (onDestroyed)
          this.#worker.removeEventListener("message", onDestroyed);
      } catch {
        /* empty */
      }
      try {
        if (onError) this.#worker.removeEventListener("error", onError);
      } catch {
        /* empty */
      }
    };

    const destroyPromise = new Promise<void>((resolve) => {
      onDestroyed = (event: MessageEvent) => {
        try {
          const data = event.data;
          if (isDestroyedResponse(data)) {
            cleanupListeners();
            resolve();
          }
        } catch {
          cleanupListeners();
          resolve();
        }
      };
      onError = () => {
        cleanupListeners();
        resolve();
      };
      this.#worker.addEventListener("message", onDestroyed);
      this.#worker.addEventListener("error", onError);
      try {
        this.#worker.postMessage({ type: "destroy" });
      } catch {
        /* ignore */
      }
    });

    const timeoutMs = this.#destroyAckTimeoutMs;
    await Promise.race([
      destroyPromise,
      new Promise<void>((resolve) => {
        destroyTimer = setTimeout(() => {
          cleanupListeners();
          resolve();
        }, timeoutMs);
      }),
    ]).finally(() => {
      if (destroyTimer) clearTimeout(destroyTimer);
      try {
        this.#worker.terminate();
      } catch {
        /* empty */
      }
      this.#cleanup();
    });
  }

  /* ========================= Pure state transitions ========================= */

  /** Create new state with updated active ports (immutable) */
  #withActivePorts(activePorts: ReadonlyMap<MessagePort, ActivePortMeta>): SignerState {
    return { ...this.#state, activePorts };
  }

  /** Create new state with updated circuit breaker (immutable) */
  #withCircuitBreaker(circuitBreaker: CircuitBreakerStatus): SignerState {
    return { ...this.#state, circuitBreaker };
  }

  /** Create new state with destroyed flag (immutable) */
  #withDestroyed(destroyed: boolean): SignerState {
    return { ...this.#state, destroyed };
  }

  /* ========================= Private helpers ========================= */

  static async #validateAndFetchWorkerScript(
    url: URL,
    init: SecureApiSignerInit,
  ): Promise<string | undefined> {
    const integrity: IntegrityMode = init.integrity ?? "compute";
    // Enforce: refuse 'compute' integrity mode in production unless explicitly allowed.
    if (
      integrity === "compute" &&
      environment.isProduction &&
      !init.allowComputeIntegrityInProduction
    ) {
      throw new InvalidConfigurationError(
        "Integrity mode 'compute' is not allowed in production. Provide expectedWorkerScriptHash and use integrity: 'require', or explicitly set allowComputeIntegrityInProduction: true after validating immutable, fingerprinted worker deployment.",
      );
    }
    if (integrity === "require") {
      if (!init.expectedWorkerScriptHash) {
        throw new InvalidParameterError(
          "integrity='require' requires expectedWorkerScriptHash.",
        );
      }
      const scriptBuf = await fetchAndValidateScript(url);
      const actualHash = await sha256Base64(scriptBuf);
      if (actualHash !== init.expectedWorkerScriptHash) {
        throw new WorkerError(
          `Worker script integrity mismatch. Expected ${init.expectedWorkerScriptHash}, got ${actualHash}.`,
        );
      }
      return actualHash;
    }
    if (integrity === "compute") {
      try {
        const scriptBuf = await fetchAndValidateScript(url);
        return await sha256Base64(scriptBuf);
      } catch (error_) {
        throw error_ instanceof Error
          ? error_
          : new WorkerError(String(error_));
      }
    }
    return undefined; // integrity === 'none'
  }

  static #initializeWorkerAndSigner(
    url: URL,
    init: SecureApiSignerInit,
    computedHash?: string,
  ): SecureApiSigner {
    const worker = new Worker(String(url), {
      type: init.useModuleWorker ? "module" : "classic",
    });
    return new SecureApiSigner(worker, init, computedHash);
  }

  async #transferSecretAndHandshake(init: SecureApiSignerInit): Promise<void> {
    const handshakeTimeoutMs =
      init.requestHandshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    const handshakeTimer = setTimeout(() => {
      this.#rejectReady(new WorkerError("Worker initialization timed out."));
    }, handshakeTimeoutMs);
    void this.#ready.finally(() => clearTimeout(handshakeTimer));

    try {
      // Accept ArrayBuffer or any ArrayBuffer view (Uint8Array, Buffer, DataView, etc.)
      if (
        !(init.secret instanceof ArrayBuffer || ArrayBuffer.isView(init.secret))
      ) {
        throw new InvalidParameterError(
          "secret must be ArrayBuffer or an ArrayBuffer view (e.g. Uint8Array)",
        );
      }
      const wipeProvided = init.wipeProvidedSecret !== false;
      const transferBuffer = prepareTransferBuffer(init.secret, wipeProvided);
      const initMessage: InitMessage = {
        type: "init",
        secretBuffer: transferBuffer,
        workerOptions: {
          dev: environment.isDevelopment,
          maxConcurrentSigning: Math.min(this.#maxPendingRequests, 1000),
        },
        ...(init.kid && { kid: init.kid }),
      };
      this.#worker.postMessage(initMessage, [transferBuffer]);
    } catch (error) {
      try {
        await this.destroy();
      } catch {
        /* ignore */
      }
      const error_ =
        error instanceof Error ? error : new WorkerError(String(error));
      throw new WorkerError(
        `Failed to post secret to worker: ${error_.message}`,
      );
    }

    try {
      await this.#performHandshake();
    } catch (error) {
      try {
        await this.destroy();
      } catch {
        /* ignore */
      }
      throw error;
    }
  }

  readonly #performHandshake = async (): Promise<void> => {
    const channel = new MessageChannel();
    const { port1: localPort, port2: workerPort } = channel;

    const timerMs = HANDSHAKE_TIMEOUT_MS;
    let handshakeTimer: ReturnType<typeof setTimeout> | undefined;

    const nonceBuf = new Uint8Array(HANDSHAKE_NONCE_BYTES);
    crypto.getRandomValues(nonceBuf);
    const nonceB64 = bytesToBase64(nonceBuf);

    const handshakeRequest = { type: "handshake", nonce: nonceB64 };

    try {
      const p = new Promise<void>((resolve, reject) => {
        handshakeTimer = setTimeout(() => {
          try {
            localPort.close();
          } catch {
            /* empty */
          }
          reject(new WorkerError("Handshake timed out"));
        }, timerMs);

        localPort.onmessage = (event: MessageEvent) => {
          if (handshakeTimer) clearTimeout(handshakeTimer);
          const data = event.data;
          try {
            if (isHandshakeResponse(data)) {
              if (!isLikelyBase64(data.signature)) {
                reject(
                  new WorkerError("Handshake response signature malformed"),
                );
              } else {
                resolve();
              }
            } else if (isErrorResponse(data)) {
              reject(new WorkerError(`Worker handshake error: ${data.reason}`));
            } else {
              reject(
                new WorkerError("Worker handshake returned unexpected message"),
              );
            }
          } catch (error) {
            reject(
              error instanceof Error ? error : new WorkerError(String(error)),
            );
          } finally {
            try {
              localPort.close();
            } catch {
              /* empty */
            }
          }
        };
      });

      this.#worker.postMessage(handshakeRequest, [workerPort]);
      await p;
      this.#resolveReady();
    } catch (error) {
      this.#rejectReady(
        error instanceof Error ? error : new WorkerError(String(error)),
      );
      throw error;
    } finally {
      if (handshakeTimer) clearTimeout(handshakeTimer);
    }
  };

  readonly #postSignRequest = (canonical: string): Promise<string> => {
    return new Promise<string>((resolve, reject) => {
      const channel = new MessageChannel();
      const { port1: localPort, port2: workerPort } = channel;

        const timer = setTimeout(() => {
        this.#removeActivePort(localPort);
        try {
          localPort.close();
        } catch {
          /* empty */
        }
        reject(new WorkerError("Sign request timed out"));
      }, this.#requestTimeoutMs);

      localPort.onmessage = (event: MessageEvent) => {
        clearTimeout(timer);
        const data: unknown = event.data;
        try {
          if (isSignedMessage(data)) {
            resolve(data.signature);
          } else if (isErrorResponse(data)) {
            const raw = data as { readonly [key: string]: unknown };
            const reason = typeof raw["reason"] === "string" ? raw["reason"] : "Worker error";
            reject(new WorkerError(reason));
          } else {
            reject(new WorkerError("Worker returned malformed response"));
          }
        } finally {
          this.#removeActivePort(localPort);
          try {
            localPort.close();
          } catch {
            /* empty */
          }
        }
      };

      this.#addActivePort(localPort, { port: localPort, reject, timer });

      const requestId = generateRequestId();
      const request: SignRequest = { type: "sign", requestId, canonical };
      try {
        this.#worker.postMessage(request, [workerPort]);
      } catch (error) {
        clearTimeout(timer);
        this.#removeActivePort(localPort);
        try {
          localPort.close();
        } catch {
          /* empty */
        }
        reject(error instanceof Error ? error : new WorkerError(String(error)));
      }
    });
  };

  async #computeCanonical(
    payload: unknown,
    context: SignContext | undefined,
    timestamp: number,
    nonce: string,
  ): Promise<string> {
    const payloadString = safeStableStringify(payload);
    const bodyString = safeStableStringify(context?.body ?? undefined);
    const bodyHash = context?.body
      ? await sha256Base64(SHARED_ENCODER.encode(bodyString))
      : "";
    return [
      timestamp,
      nonce,
      (context?.method ?? "").toUpperCase(),
      context?.path ?? "",
      bodyHash,
      payloadString,
      this.#kid ?? "",
    ].join(".");
  }

  /* ========================= Event handlers ========================= */

  readonly #handleWorkerMessage = (event: MessageEvent): void => {
    const data = event.data as WorkerMessage;
    try {
      if (isInitResponse(data)) {
        this.#safeResolveReady();
      } else if (isErrorResponse(data)) {
        const error = new WorkerError(data.reason ?? "Worker error");
        // Reject ready in case handshake was pending
        this.#safeRejectReady(error);
        // Reject currently pending requests but keep signer alive for circuit-breaker
        try {
          this.#rejectAllPending(error);
        } catch {
          /* ignore */
        }
      } else if (isDestroyedResponse(data)) {
        this.#cleanup();
      } else {
        // ignore unknown top-level message
      }
    } catch (error) {
      const error_ =
        error instanceof Error ? error : new WorkerError(String(error));
      this.#safeRejectReady(error_);
      this.#rejectAllPending(error_);
      this.#cleanup();
    }
  };

  readonly #handleWorkerError = (event: Event | MessageEvent): void => {
    const message = (event as ErrorEvent).message ?? "Worker error";
    const error = new WorkerError(message);
    this.#safeRejectReady(error);
    try {
      this.#rejectAllPending(error);
    } catch {
      /* ignore */
    }
    // Do not fully cleanup/destroy here; allow circuit breaker to open and tests to recover
  };

  readonly #cleanup = (): void => {
    try {
      this.#worker.removeEventListener("message", this.#handleWorkerMessage);
      this.#worker.removeEventListener("error", this.#handleWorkerError);
      this.#worker.removeEventListener("messageerror", this.#handleWorkerError);
    } catch {
      /* ignore */
    }
    this.#rejectAllPending(new WorkerError("Signer destroyed"));
  };

  readonly #rejectAllPending = (error: Error): void => {
    this.#state.activePorts.forEach((meta) => {
      try {
        clearTimeout(meta.timer);
        meta.reject(error);
        try {
          meta.port.close();
        } catch {
          /* empty */
        }
      } catch {
        /* ignore */
      }
    });
    this.#state = this.#withActivePorts(new Map());
  };

  // Safe wrappers to avoid unhandled rejections if promise already settled
  readonly #safeRejectReady = (reason: unknown): void => {
    try {
      this.#rejectReady(reason);
    } catch {
      /* ignore */
    }
  };
  readonly #safeResolveReady = (): void => {
    try {
      this.#resolveReady();
    } catch {
      /* ignore */
    }
  };

  readonly #addActivePort = (port: MessagePort, meta: ActivePortMeta): void => {
    // create a new Map to keep an immutable transition
    const newActivePorts = new Map(this.#state.activePorts);
    newActivePorts.set(port, meta);
    this.#state = this.#withActivePorts(newActivePorts);
  };

  readonly #removeActivePort = (port: MessagePort): void => {
    // immutable transition: construct a new map without the port
    const newActivePorts = new Map<MessagePort, ActivePortMeta>();
    this.#state.activePorts.forEach((meta, currentPort) => {
      if (currentPort === port) {
        try {
          clearTimeout(meta.timer);
        } catch {
          /* ignore */
        }
        return;
      }
      newActivePorts.set(currentPort, meta);
    });
    this.#state = this.#withActivePorts(newActivePorts);
  };

  /* ========================= Circuit breaker logic ========================= */

  readonly #checkCircuitBreaker = (): void => {
    if (this.#state.circuitBreaker.state === "open") {
      if (
        Date.now() - this.#state.circuitBreaker.lastFailureTime >
        CIRCUIT_BREAKER_TIMEOUT_MS
      ) {
        const newCircuitBreaker = {
          state: "half-open" as const,
          failureCount: this.#state.circuitBreaker.failureCount,
          lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
          successCount: 0,
        };
        this.#state = this.#withCircuitBreaker(newCircuitBreaker);
      } else {
        throw new CircuitBreakerError();
      }
    }
  };

  readonly #recordSuccess = (): void => {
    if (this.#state.circuitBreaker.state === "half-open") {
      const newSuccessCount = this.#state.circuitBreaker.successCount + 1;
      if (newSuccessCount >= CIRCUIT_BREAKER_SUCCESS_THRESHOLD) {
        const newCircuitBreaker = {
          state: "closed" as const,
          failureCount: 0,
          lastFailureTime: 0,
          successCount: 0,
        };
        this.#state = this.#withCircuitBreaker(newCircuitBreaker);
      } else {
        const newCircuitBreaker = {
          state: this.#state.circuitBreaker.state,
          failureCount: this.#state.circuitBreaker.failureCount,
          lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
          successCount: newSuccessCount,
        };
        this.#state = this.#withCircuitBreaker(newCircuitBreaker);
      }
    } else {
      const newFailureCount = Math.max(
        0,
        this.#state.circuitBreaker.failureCount - 1,
      );
      const newCircuitBreaker = {
        state: this.#state.circuitBreaker.state,
        failureCount: newFailureCount,
        lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
        successCount: this.#state.circuitBreaker.successCount,
      };
      this.#state = this.#withCircuitBreaker(newCircuitBreaker);
    }
  };

  readonly #recordFailure = (): void => {
    const newFailureCount = this.#state.circuitBreaker.failureCount + 1;
    if (
      this.#state.circuitBreaker.state === "half-open" ||
      newFailureCount >= CIRCUIT_BREAKER_FAILURE_THRESHOLD
    ) {
      const newCircuitBreaker = {
        state: "open" as const,
        failureCount: newFailureCount,
        lastFailureTime: Date.now(),
        successCount: this.#state.circuitBreaker.successCount,
      };
      this.#state = this.#withCircuitBreaker(newCircuitBreaker);
    } else {
      const newCircuitBreaker = {
        state: this.#state.circuitBreaker.state,
        failureCount: newFailureCount,
        lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
        successCount: this.#state.circuitBreaker.successCount,
      };
      this.#state = this.#withCircuitBreaker(newCircuitBreaker);
    }
  };

  /* ========================= Observability ========================= */

  public getCircuitBreakerStatus(): CircuitBreakerStatus {
    return { ...this.#state.circuitBreaker };
  }
  public getPendingRequestCount(): number {
    return this.#state.activePorts.size;
  }
  public isDestroyed(): boolean {
    return this.#state.destroyed;
  }
  /** If integrity === 'compute', consumers can read this (useful for telemetry / debugging). */
  public getComputedWorkerHash(): string | undefined {
    return this.#computedWorkerHash;
  }
}

/* ========================= Helper: fetch and validate script ========================= */

/** Fetches the worker script at `url`, asserts no redirects, and returns ArrayBuffer. */
async function fetchAndValidateScript(url: URL): Promise<ArrayBuffer> {
  let response: Response;
  try {
    // redirect: "error" causes fetch to throw on redirect in modern browsers.
    response = await fetch(String(url), {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
    });
  } catch (error) {
    throw error instanceof Error ? error : new WorkerError(String(error));
  }
  if (!response.ok)
    throw new WorkerError(
      `Failed to fetch worker script: ${response.status} ${response.statusText}`,
    );
  // defensive: ensure no redirect occurred
  const redirected = "redirected" in response && response.redirected === true;
  if (redirected || response.url !== String(url)) {
    throw new WorkerError(
      "Worker script fetch was redirected; refusing to proceed.",
    );
  }
  return await response.arrayBuffer();
}
