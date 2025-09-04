// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// SecureApiSigner — hardened TypeScript implementation with strict integrity defaults
//
// Integrity strategy:
// - `integrity` controls behavior: "require" | "compute" | "none"
//   - "require": a build-time `expectedWorkerScriptHash` (base64 SHA-256) MUST be provided (strict; default).
//   - "compute": the library will fetch the worker script at runtime, compute its hash and proceed (dev-friendly).
//   - "none": skip script hash checks entirely (forbidden in production).
// - When runtime policy enables Blob workers AND Blob URLs, the signer creates the Worker from the verified bytes
//   to eliminate the TOCTOU window. Otherwise, URL-based Worker creation is used as a fallback with explicit guards.

import {
  InvalidParameterError,
  WorkerError,
  RateLimitError,
  CircuitBreakerError,
  SecurityKitError,
} from "./errors";
import { safeStableStringify } from "./canonical.js";
//   in security-sensitive deployments. "compute" is the pragmatic default for npm consumers.
// - Other hardenings retained: binary-only secrets, handshake, strict runtime guards, canonicalization,
//   best-effort wiping, rigorous port cleanup, and fixed destroy listener removal.
//
// NOTE: For maximum security in production, CI should compute `expectedWorkerScriptHash` and the integritiy mode should be "require".
// If that's impractical for your consumers, "compute" offers portability at the cost of the remaining TOCTOU risk.

import { getSecureRandomBytesSync } from "./crypto";
import { SHARED_ENCODER } from "./encoding";
import {
  bytesToBase64,
  base64ToBytes,
  sha256Base64,
  isLikelyBase64,
  secureWipeWrapper,
} from "./encoding-utils";
import { environment } from "./environment";
import type {
  InitMessage,
  SignRequest,
  ErrorResponse,
  WorkerMessage,
  SignedResponse,
} from "./protocol";
import { getLoggingConfig, getRuntimePolicy } from "./config";
import { VerifiedByteCache } from "./secure-cache";
import { secureCompare, secureDevelopmentLog } from "./utils";

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
const DEFAULT_MAX_CANONICAL_LENGTH = 2_000_000; // 2MB limit to prevent DoS

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

  // NEW: explicit rate limiting knobs for the worker
  readonly rateLimitPerMinute?: number;
  readonly maxConcurrentSigning?: number;

  // NEW: optional handshake policy overrides to prevent config drift
  readonly handshakeMaxNonceLength?: number;
  readonly allowedNonceFormats?: readonly import("./constants").NonceFormat[];
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
  const bytes = getSecureRandomBytesSync(4);
  // Convert to positive 32-bit integer, Uint8Array indices are guaranteed to exist
  return (
    (((bytes[0] ?? 0) << 24) |
      ((bytes[1] ?? 0) << 16) |
      ((bytes[2] ?? 0) << 8) |
      (bytes[3] ?? 0)) >>>
    0
  );
}

/* ========================= Utilities ========================= */

// Use shared encoding-utils for base64/hash/wipe helpers

// Small, conservative cross-call cache for canonical JSON strings.
// WeakMap ensures GC-bound entries; we only cache deeply frozen roots (shallow audit)
// with primitive or frozen nested values to avoid stale reads after mutation.
const STRINGIFY_CACHE: WeakMap<object, string> = new WeakMap();

function canCacheRoot(root: unknown): boolean {
  if (root === null || typeof root !== "object") return false;
  if (!Object.isFrozen(root)) return false;

  if (Array.isArray(root)) {
    return canCacheArrayRoot(root);
  }

  return canCacheObjectRoot(root as Record<string, unknown>);
}

function canCacheArrayRoot(array: readonly unknown[]): boolean {
  for (const v of array) {
    if (v === null) continue;
    if (!isCacheablePrimitive(v) && !isCacheableFrozenObject(v)) {
      return false;
    }
  }
  return true;
}

function canCacheObjectRoot(object: Record<string, unknown>): boolean {
  const keys = Object.keys(object);
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(object, k);
    if (!d || !d.enumerable || !("value" in d)) return false;
    const v: unknown = d.value as unknown;
    if (v === null) continue;
    if (!isCacheablePrimitive(v) && !isCacheableFrozenObject(v)) {
      return false;
    }
  }
  return true;
}

function isCacheablePrimitive(v: unknown): boolean {
  const t = typeof v;
  if (t === "string" || t === "boolean") return true;
  if (t === "number") {
    // OWASP ASVS L3: Type guard for Number.isFinite to prevent unsafe type assertions
    return Number.isFinite(v as number);
  }
  return false;
}

function isCacheableFrozenObject(v: unknown): boolean {
  if (typeof v === "object" && v !== null) {
    // OWASP ASVS L3: Type guard for Object.isFrozen to prevent unsafe type assertions
    // Use a more specific type assertion that satisfies the linter
    const object = v as Record<string, unknown>;
    return Object.isFrozen(object);
  }
  return false;
}

function stringifyWithCache(value: unknown): string {
  if (value !== null && typeof value === "object") {
    const cached = STRINGIFY_CACHE.get(value);
    if (cached !== undefined) return cached;
    if (canCacheRoot(value)) {
      const s = safeStableStringify(value);
      STRINGIFY_CACHE.set(value, s);
      return s;
    }
  }
  return safeStableStringify(value);
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
  // Only allow http(s) schemes for worker URLs
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InvalidParameterError(
      `workerUrl must use http(s) scheme, got ${url.protocol}`,
    );
  }
  // In production, require HTTPS to avoid mixed content and downgrade risks
  if (environment.isProduction && url.protocol !== "https:") {
    throw new InvalidParameterError(
      `In production, workerUrl must use https:, got ${url.protocol}`,
    );
  }
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
  readonly #handshakeTimeoutMs: number;
  readonly #destroyAckTimeoutMs: number;
  readonly #computedWorkerHash: string | undefined;

  // NEW: Store rate limiting configuration for observability
  readonly #rateLimitPerMinute: number;
  readonly #maxConcurrentSigning: number;

  // eslint-disable-next-line functional/prefer-readonly-type -- These fields are intentionally mutable for state management
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
  // Reservation tokens to synchronously reserve pending slots before async work
  // eslint-disable-next-line functional/prefer-readonly-type -- These fields are intentionally mutable for state management
  #pendingReservations = 0;
  readonly #reservationTokens = new Set<number>();
  // eslint-disable-next-line functional/prefer-readonly-type -- These fields are intentionally mutable for state management
  #nextReservationId = 1;
  // Track created blob URLs for cleanup to avoid leaking object URLs
  // Legacy compatibility Set (kept for external expectations); do not mutate directly
  // eslint-disable-next-line functional/prefer-readonly-type
  readonly _createdBlobUrls: Set<string> = new Set();
  // Preferred immutable list for internal tracking
  // eslint-disable-next-line functional/prefer-readonly-type
  #blobUrls: readonly string[] = [];
  // #pendingReservations provides synchronous slot reservation to prevent races under concurrent sign() calls.
  // Concurrency is enforced via the size of #state.activePorts after reservation is converted into an active port.
  // eslint-disable-next-line functional/prefer-readonly-type -- These fields are intentionally mutable for state management
  #resolveReady!: () => void;
  // eslint-disable-next-line functional/prefer-readonly-type -- These fields are intentionally mutable for state management
  #rejectReady!: (reason: unknown) => void;

  private constructor(
    worker: Worker,
    options: SecureApiSignerInit,
    computedHash?: string,
  ) {
    this.#worker = worker;
    this.#kid = options.kid;

    // Initialize basic configuration first
    this.#requestTimeoutMs =
      options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.#maxPendingRequests =
      options.maxPendingRequests ?? DEFAULT_MAX_PENDING_REQUESTS;
    this.#destroyAckTimeoutMs =
      options.destroyAckTimeoutMs ?? DEFAULT_DESTROY_ACK_TIMEOUT_MS;
    this.#computedWorkerHash = computedHash;
    this.#handshakeTimeoutMs =
      options.requestHandshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;

    // Compute and store rate limiting configuration
    const cfg = getLoggingConfig();
    this.#rateLimitPerMinute =
      typeof options.rateLimitPerMinute === "number"
        ? Math.max(0, Math.floor(options.rateLimitPerMinute))
        : Math.max(0, Math.floor(cfg.rateLimitTokensPerMinute ?? 0));

    this.#maxConcurrentSigning =
      typeof options.maxConcurrentSigning === "number"
        ? Math.min(Math.max(1, Math.floor(options.maxConcurrentSigning)), 1000)
        : Math.min(this.#maxPendingRequests, 1000);

    this.#ready = new Promise<void>((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });

    this.#worker.addEventListener("message", this.#handleWorkerMessage);
    this.#worker.addEventListener("error", this.#handleWorkerError);
    this.#worker.addEventListener("messageerror", this.#handleWorkerError);
  }

  /**
   * Create signer factory. Integrity defaults to 'require' for maximum security.
   * For production deployments, always provide expectedWorkerScriptHash and use integrity: 'require'.
   */
  public static async create(
    init: SecureApiSignerInit & { readonly integrity?: IntegrityMode },
  ): Promise<SecureApiSigner> {
    // Validate basic parameters first
    if (
      init.integrity !== undefined &&
      !["require", "compute", "none"].includes(init.integrity)
    ) {
      throw new InvalidParameterError(
        `Invalid integrity mode: ${init.integrity}. Must be 'require', 'compute', or 'none'.`,
      );
    }

    if (init.integrity === undefined) {
      throw new InvalidParameterError(
        'integrity mode cannot be undefined. Use "require", "compute", or "none".',
      );
    }

    // Validate configuration parameters
    if (
      init.maxPendingRequests !== undefined &&
      (typeof init.maxPendingRequests !== "number" ||
        init.maxPendingRequests < 1 ||
        !Number.isInteger(init.maxPendingRequests))
    ) {
      throw new InvalidParameterError(
        "maxPendingRequests must be a positive integer.",
      );
    }

    if (
      init.requestTimeoutMs !== undefined &&
      (typeof init.requestTimeoutMs !== "number" ||
        init.requestTimeoutMs <= 0 ||
        !Number.isInteger(init.requestTimeoutMs))
    ) {
      throw new InvalidParameterError(
        "requestTimeoutMs must be a positive integer.",
      );
    }

    if (
      init.destroyAckTimeoutMs !== undefined &&
      (typeof init.destroyAckTimeoutMs !== "number" ||
        init.destroyAckTimeoutMs < 0 ||
        !Number.isInteger(init.destroyAckTimeoutMs))
    ) {
      throw new InvalidParameterError(
        "destroyAckTimeoutMs must be a non-negative integer.",
      );
    }

    // Change default: require strict integrity unless explicitly overridden.
    const integrity: IntegrityMode = init.integrity ?? "require";

    // Validate integrity mode and production constraints
    SecureApiSigner.#validateIntegrityMode(integrity, init);

    // Validate and normalize worker URL
    const url = SecureApiSigner.#validateAndNormalizeWorkerUrl(init);

    // Validate/fetch script per chosen integrity mode
    const computedHash = await SecureApiSigner.#validateAndFetchWorkerScript(
      url,
      init,
      integrity,
    );

    // Initialize worker and signer
    const signer = SecureApiSigner.#initializeWorkerAndSigner(
      url,
      init,
      computedHash,
      integrity,
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
        if (bytes instanceof Uint8Array) {
          secureWipeWrapper(bytes);
        }
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
    if (this.#state.destroyed)
      throw new InvalidParameterError("Signer destroyed");
    this.#checkCircuitBreaker();
    // Reserve a pending slot synchronously to avoid races when many callers invoke
    // sign() concurrently. The reservation will be converted to an active port
    // when #postSignRequest calls #addActivePort, which drains one token.
    const reservationId = this.#reservePendingSlot();
    try {
      await this.#ready;
    } catch (error) {
      // release reservation if readiness failed
      this.#releaseReservationIfPresent(reservationId);
      throw error;
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
      // If our reservation was never converted to an active port, release it now.
      this.#releaseReservationIfPresent(reservationId);
    }
  }

  /** Destroy: graceful with ack, always cleans up listeners (fixed race) */
  public async destroy(): Promise<void> {
    if (this.#state.destroyed) return;
    // eslint-disable-next-line functional/immutable-data -- controlled state transition
    this.#state = this.#withDestroyed(true);

    // eslint-disable-next-line functional/no-let -- temporary variables for cleanup
    let destroyTimer: ReturnType<typeof setTimeout> | undefined;
    // eslint-disable-next-line functional/no-let -- temporary variables for cleanup
    let onDestroyed: ((event: MessageEvent) => void) | undefined;
    // eslint-disable-next-line functional/no-let -- temporary variables for cleanup
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
          const data: unknown = event.data;
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
      try {
        for (const u of this.#blobUrls) {
          try {
            URL.revokeObjectURL(String(u));
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* ignore */
      }
      this.#cleanup();
    });
  }

  /* ========================= Pure state transitions ========================= */

  /** Create new state with updated active ports (immutable) */
  #withActivePorts(
    activePorts: ReadonlyMap<MessagePort, ActivePortMeta>,
  ): SignerState {
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

  // Track blob URLs immutably and mirror to legacy Set for external read-only use
  #trackBlobUrl(url: string): void {
    // Replace the internal list reference immutably
    // eslint-disable-next-line functional/immutable-data -- controlled append to internal list reference
    this.#blobUrls = [...this.#blobUrls, url];
    try {
      // eslint-disable-next-line functional/immutable-data
      this._createdBlobUrls.add(url);
    } catch {
      /* ignore */
    }
  }

  static #validateIntegrityMode(
    integrity: IntegrityMode,
    init: SecureApiSignerInit & { readonly integrity?: IntegrityMode },
  ): void {
    const policy = getRuntimePolicy();

    // Validate integrity mode is valid
    if (!["require", "compute", "none"].includes(integrity)) {
      throw new InvalidParameterError(
        `Invalid integrity mode: ${integrity}. Must be 'require', 'compute', or 'none'.`,
      );
    }

    // 'none' is forbidden in production for security
    if (integrity === "none" && environment.isProduction) {
      throw new SecurityKitError(
        "Integrity mode 'none' is forbidden in production. Use 'require' or 'compute' with proper security controls.",
        "E_INTEGRITY_REQUIRED",
      );
    }

    // 'require' demands expected hash
    if (
      integrity === "require" &&
      typeof init.expectedWorkerScriptHash !== "string"
    ) {
      throw new SecurityKitError(
        "Integrity mode 'require' demands expectedWorkerScriptHash (base64 SHA-256).",
        "E_INTEGRITY_REQUIRED",
      );
    }

    // Fail early if 'compute' is attempted in production without explicit OK
    if (
      integrity === "compute" &&
      environment.isProduction &&
      !(
        init.allowComputeIntegrityInProduction &&
        policy.allowComputeIntegrityInProductionDefault
      )
    ) {
      throw new SecurityKitError(
        "Integrity mode 'compute' is not allowed in production. Provide expectedWorkerScriptHash and use integrity: 'require', or explicitly allow 'compute' in production via BOTH init.allowComputeIntegrityInProduction AND setRuntimePolicy({ allowComputeIntegrityInProductionDefault: true }).",
        "E_INTEGRITY_REQUIRED",
      );
    }
  }

  static #validateAndNormalizeWorkerUrl(
    init: SecureApiSignerInit & { readonly integrity?: IntegrityMode },
  ): URL {
    return normalizeAndValidateWorkerUrl(
      init.workerUrl,
      init.allowCrossOriginWorkerOrigins,
    );
  }

  static async #validateAndFetchWorkerScript(
    url: URL,
    init: SecureApiSignerInit,
    integrity: IntegrityMode,
  ): Promise<string | undefined> {
    const policy = getRuntimePolicy();
    // 'require' demands expected hash
    if (
      integrity === "require" &&
      typeof init.expectedWorkerScriptHash !== "string"
    ) {
      throw new SecurityKitError(
        "Integrity mode 'require' demands expectedWorkerScriptHash (base64 SHA-256).",
        "E_INTEGRITY_REQUIRED",
      );
    }

    // Fail early if 'compute' is attempted in production without explicit OK
    if (
      integrity === "compute" &&
      environment.isProduction &&
      !(
        init.allowComputeIntegrityInProduction &&
        policy.allowComputeIntegrityInProductionDefault
      )
    ) {
      throw new SecurityKitError(
        "Integrity mode 'compute' is not allowed in production. Provide expectedWorkerScriptHash and use integrity: 'require', or explicitly allow 'compute' in production via BOTH init.allowComputeIntegrityInProduction AND setRuntimePolicy({ allowComputeIntegrityInProductionDefault: true }).",
        "E_INTEGRITY_REQUIRED",
      );
    }

    // Fetch script bytes when 'compute' or when we want to verify expected hash
    const needFetch =
      integrity === "compute" ||
      typeof init.expectedWorkerScriptHash === "string" ||
      (integrity === "require" && getRuntimePolicy().allowBlobWorkers);

    if (!needFetch) return undefined;

    const bytes = await fetchAndValidateScript(url);
    const hash = await sha256Base64(bytes);

    if (typeof init.expectedWorkerScriptHash === "string") {
      if (!secureCompare(hash, init.expectedWorkerScriptHash)) {
        throw new SecurityKitError(
          "Worker script integrity mismatch.",
          "E_SIGNATURE_MISMATCH",
        );
      }
    }

    // Store verified bytes for Blob worker creation if Blob workers are allowed
    if (
      (integrity === "compute" || integrity === "require") &&
      policy.allowBlobWorkers &&
      policy.enableWorkerByteCache
    ) {
      VerifiedByteCache.set(url.href, new Uint8Array(bytes));
    }

    return hash;
  }

  // eslint-disable-next-line sonarjs/cognitive-complexity -- Security-critical branching kept explicit and small; further refactor would obscure error handling
  static #initializeWorkerAndSigner(
    url: URL,
    init: SecureApiSignerInit,
    computedHash?: string,
    integrity?: IntegrityMode,
  ): SecureApiSigner {
    const policy = getRuntimePolicy();
    const canBlob =
      (integrity === "compute" || integrity === "require") &&
      policy.allowBlobWorkers &&
      policy.allowBlobUrls;

    if (canBlob) {
      const cachedBytes = VerifiedByteCache.get(url.href);
      if (cachedBytes) {
        // Ensure any created blob URL is revoked on failure to avoid leaks
        // eslint-disable-next-line functional/no-let -- temporary holder for cleanup
        let blobUrl: string | undefined;
        try {
          const copied = new Uint8Array(cachedBytes);
          const blob = new Blob([copied.buffer], { type: "text/javascript" });
          blobUrl = URL.createObjectURL(blob);
          const worker = new Worker(blobUrl, {
            type: init.useModuleWorker ? "module" : "classic",
          });
          const signer = new SecureApiSigner(worker, init, computedHash);
          signer.#trackBlobUrl(blobUrl);
          return signer;
        } catch {
          // Best-effort revoke if blobUrl was created prior to failure
          try {
            if (blobUrl) URL.revokeObjectURL(blobUrl);
          } catch (error) {
            // Log at debug level in development only; continue with secure failure.
            try {
              secureDevelopmentLog(
                "debug",
                "secure-api-signer",
                "revokeObjectURL failed during CSP cleanup",
                { error: String(error) },
              );
            } catch {
              /* ignore secondary log failures */
            }
          }
          // Fail closed for CSP violations regardless of environment to enforce
          // strict policy and surface misconfiguration early (ASVS L3 posture).
          throw new SecurityKitError(
            "Blob worker creation blocked (likely by CSP).",
            "E_CSP_BLOCKED",
          );
        }
      }
      // In production + 'require' + Blob allowed, if we do not have verified bytes
      // available (e.g., cache disabled), do NOT fall back to URL worker — fail loud.
      if (environment.isProduction && integrity === "require") {
        throw new SecurityKitError(
          "Verified worker bytes unavailable for Blob instantiation; enable worker byte cache or disable Blob workers.",
          "E_CONFIG",
        );
      }
    }

    // Fallback to URL worker
    const worker = new Worker(String(url), {
      type: init.useModuleWorker ? "module" : "classic",
    });
    return new SecureApiSigner(worker, init, computedHash);
  }

  async #transferSecretAndHandshake(init: SecureApiSignerInit): Promise<void> {
    const handshakeTimer = setTimeout(() => {
      this.#rejectReady(new WorkerError("Worker initialization timed out."));
    }, this.#handshakeTimeoutMs);
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

      // Build worker options object with proper typing
      const baseWorkerOptions = {
        rateLimitPerMinute: this.#rateLimitPerMinute,
        maxConcurrentSigning: this.#maxConcurrentSigning,
        dev: environment.isDevelopment,
      };

      // Add handshake overrides if provided to prevent config drift
      const workerOptions = {
        ...baseWorkerOptions,
        ...(init.handshakeMaxNonceLength !== undefined && {
          handshakeMaxNonceLength: Math.max(
            1,
            Math.floor(init.handshakeMaxNonceLength),
          ),
        }),
        ...(init.allowedNonceFormats !== undefined && {
          allowedNonceFormats: init.allowedNonceFormats,
        }),
      };

      const initMessage: InitMessage = {
        type: "init",
        secretBuffer: transferBuffer,
        workerOptions,
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

    const timerMs = this.#handshakeTimeoutMs;
    const nonceBuf = getSecureRandomBytesSync(HANDSHAKE_NONCE_BYTES);
    const nonceB64 = bytesToBase64(nonceBuf);

    const handshakeRequest = { type: "handshake", nonce: nonceB64 };

    // Local timer id so we can clear timeout in finally
    // eslint-disable-next-line functional/no-let -- timerId is reassigned in finally
    let timerId: ReturnType<typeof setTimeout> | undefined;

    const handshakePromise = new Promise<void>((resolve, reject) => {
      // idempotent cleanup helper for handler
      const cleanupHandler = () => {
        try {
          // eslint-disable-next-line -- Clearing event handler
          localPort.onmessage = null;
        } catch {
          /* ignore */
        }
        try {
          localPort.close();
        } catch {
          /* ignore */
        }
      };

      // assign handler
      // eslint-disable-next-line functional/immutable-data -- Controlled assignment for lifecycle
      localPort.onmessage = (event: MessageEvent) => {
        const data: unknown = event.data;
        try {
          if (isHandshakeResponse(data)) {
            if (!isLikelyBase64(data.signature)) {
              reject(new WorkerError("Handshake response signature malformed"));
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
          cleanupHandler();
        }
      };
    });

    const timeoutPromise = new Promise<void>((_resolve, reject) => {
      timerId = setTimeout(() => {
        try {
          // eslint-disable-next-line -- Clearing event handler
          localPort.onmessage = null;
        } catch {
          /* ignore */
        }
        try {
          localPort.close();
        } catch {
          /* ignore */
        }
        reject(new WorkerError("Handshake timed out"));
      }, timerMs);
    });

    try {
      this.#worker.postMessage(handshakeRequest, [workerPort]);
      await Promise.race([handshakePromise, timeoutPromise]);
      this.#resolveReady();
    } catch (error) {
      this.#rejectReady(
        error instanceof Error ? error : new WorkerError(String(error)),
      );
      throw error;
    } finally {
      if (timerId) clearTimeout(timerId);
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

      // eslint-disable-next-line functional/immutable-data -- Controlled assignment of event handler for request lifecycle. Performance-critical path.
      localPort.onmessage = (event: MessageEvent) => {
        clearTimeout(timer);
        const data: unknown = event.data;
        try {
          if (isSignedMessage(data)) {
            resolve(data.signature);
          } else if (isErrorResponse(data)) {
            const reason =
              typeof data.reason === "string" ? data.reason : "Worker error";
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

      // When converting the reservation to an active port, consume one reserved slot
      // if available. This keeps the synchronous reservation count and activePorts
      // in balance under concurrent load.
      // If no reservation exists, allow adding the active port as fallback.
      const consumed = this.#consumeReservationIfAvailable();
      if (
        !consumed &&
        this.#state.activePorts.size >= this.#maxPendingRequests
      ) {
        // No reservation and we've hit the max; reject immediately.
        clearTimeout(timer);
        try {
          localPort.close();
        } catch {
          /* ignore */
        }
        reject(
          new RateLimitError(
            "too-many-pending-sign-requests: Maximum pending sign requests reached",
          ),
        );
        return;
      }
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
    const payloadString = stringifyWithCache(payload);
    const hasBody = context?.body !== undefined;
    const bodyString = stringifyWithCache(context?.body ?? undefined);
    const bodyHash = hasBody
      ? await sha256Base64(SHARED_ENCODER.encode(bodyString))
      : "";
    const canonical = [
      timestamp,
      nonce,
      (context?.method ?? "").toUpperCase(),
      context?.path ?? "",
      bodyHash,
      payloadString,
      this.#kid ?? "",
    ].join(".");

    // Enforce max canonical length to prevent DoS
    if (canonical.length > DEFAULT_MAX_CANONICAL_LENGTH) {
      throw new SecurityKitError(
        `Canonical string exceeds max length ${DEFAULT_MAX_CANONICAL_LENGTH}`,
        "E_PAYLOAD_SIZE",
      );
    }

    return canonical;
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
    // eslint-disable-next-line functional/immutable-data -- controlled state transition
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

    const newActivePorts = new Map([
      ...this.#state.activePorts.entries(),
      [port, meta],
    ]);
    // eslint-disable-next-line functional/immutable-data -- Controlled state transition for O(1) port addition. Encapsulated within private method.
    this.#state = this.#withActivePorts(newActivePorts);
  };

  // Reserve a pending slot synchronously. Returns reservation id.
  #reservePendingSlot(): number {
    if (
      this.#state.activePorts.size + this.#pendingReservations >=
      this.#maxPendingRequests
    ) {
      throw new RateLimitError(
        "too-many-pending-sign-requests: Maximum pending sign requests reached",
      );
    }
    // eslint-disable-next-line functional/immutable-data -- controlled reservation counter
    const id = this.#nextReservationId++;
    // eslint-disable-next-line functional/immutable-data -- controlled reservation state update
    this.#pendingReservations++;
    // eslint-disable-next-line functional/immutable-data -- controlled reservation state update
    this.#reservationTokens.add(id);
    return id;
  }

  // Consume one reservation if available. Returns true if consumed.
  #consumeReservationIfAvailable(): boolean {
    if (this.#pendingReservations <= 0 || this.#reservationTokens.size === 0) {
      return false;
    }
    // consume the first available token
    const iterator = this.#reservationTokens.values();
    const first = iterator.next();
    if (first.done) return false;

    const id = first.value;
    // eslint-disable-next-line functional/immutable-data -- controlled token removal
    this.#reservationTokens.delete(id);
    // eslint-disable-next-line functional/immutable-data -- controlled reservation state update
    this.#pendingReservations = Math.max(0, this.#pendingReservations - 1);
    return true;
  }

  // Release a reservation if it exists (called when sign() fails before conversion)
  #releaseReservationIfPresent(id: number | undefined): void {
    if (id === undefined || !this.#reservationTokens.has(id)) {
      return;
    }
    // eslint-disable-next-line functional/immutable-data -- controlled token removal
    this.#reservationTokens.delete(id);
    // eslint-disable-next-line functional/immutable-data -- controlled reservation state update
    this.#pendingReservations = Math.max(0, this.#pendingReservations - 1);
  }

  readonly #removeActivePort = (port: MessagePort): void => {
    if (this.#state.activePorts.has(port)) {
      const currentMeta = this.#state.activePorts.get(port);
      if (currentMeta) {
        try {
          clearTimeout(currentMeta.timer);
        } catch {
          /* ignore */
        }
      }

      // More efficient immutable update: filter out the port
      const newActivePorts = new Map(
        Array.from(this.#state.activePorts.entries()).filter(
          ([p]) => p !== port,
        ),
      );

      // eslint-disable-next-line functional/immutable-data -- controlled state transition
      this.#state = this.#withActivePorts(newActivePorts);
    }
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
        // eslint-disable-next-line functional/immutable-data -- controlled state transition
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
        // eslint-disable-next-line functional/immutable-data -- controlled state transition
        this.#state = this.#withCircuitBreaker(newCircuitBreaker);
      } else {
        const newCircuitBreaker = {
          state: this.#state.circuitBreaker.state,
          failureCount: this.#state.circuitBreaker.failureCount,
          lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
          successCount: newSuccessCount,
        };
        // eslint-disable-next-line functional/immutable-data -- controlled state transition
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
      // eslint-disable-next-line functional/immutable-data -- controlled state transition
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
      // eslint-disable-next-line functional/immutable-data -- controlled state transition
      this.#state = this.#withCircuitBreaker(newCircuitBreaker);
    } else {
      const newCircuitBreaker = {
        state: this.#state.circuitBreaker.state,
        failureCount: newFailureCount,
        lastFailureTime: this.#state.circuitBreaker.lastFailureTime,
        successCount: this.#state.circuitBreaker.successCount,
      };
      // eslint-disable-next-line functional/immutable-data -- controlled state transition
      this.#state = this.#withCircuitBreaker(newCircuitBreaker);
    }
  };

  /* ========================= Observability ========================= */

  public getCircuitBreakerStatus(): CircuitBreakerStatus {
    return { ...this.#state.circuitBreaker };
  }
  public getPendingRequestCount(): number {
    // Include synchronous reservations to reflect the total number of pending
    // requests (active ports + reserved slots). This makes rate-limit state
    // observable and avoids a TOCTOU where many callers reserve slots
    // concurrently but the public count only reports active ports.
    return this.#state.activePorts.size + this.#pendingReservations;
  }
  public isDestroyed(): boolean {
    return this.#state.destroyed;
  }
  /** If integrity === 'compute', consumers can read this (useful for telemetry / debugging). */
  public getComputedWorkerHash(): string | undefined {
    return this.#computedWorkerHash;
  }
  /** Get the configured rate limiting parameters for observability and debugging. */
  public getRateLimitConfig(): {
    readonly rateLimitPerMinute: number;
    readonly maxConcurrentSigning: number;
  } {
    return {
      rateLimitPerMinute: this.#rateLimitPerMinute,
      maxConcurrentSigning: this.#maxConcurrentSigning,
    };
  }
}

/* ========================= Helper: fetch and validate script ========================= */

/** Fetches the worker script at `url`, asserts no redirects, and returns ArrayBuffer. */
async function fetchAndValidateScript(url: URL): Promise<ArrayBuffer> {
  // eslint-disable-next-line functional/no-let -- response reassignment needed for error handling
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
