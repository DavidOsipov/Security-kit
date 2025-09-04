// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
/**
 * server/verify-api-request-signature.ts
 *
 * Server-side verification for signatures produced by SecureApiSigner.
 *
 * SECURITY CONSTITUTION COMPLIANCE:
 * - Implements positive validation (allowlist) for all inputs per Part II-B rules
 * - Uses timing-safe comparison to prevent timing attacks
 * - Requires explicit nonce store implementation to prevent replay attacks
 * - Validates message structure to prevent HTTP smuggling
 * - Enforces data minimization principles
 *
 * IMPORTANT: The server MUST provide a nonceStore implementing INonceStore
 * for replay protection. The example InMemoryNonceStore is NOT for production.
 */

import {
  InvalidParameterError,
  TimestampError,
  ReplayAttackError,
  SignatureVerificationError,
  InvalidConfigurationError,
} from "../src/errors.js";
import { SHARED_ENCODER } from "../src/encoding.js";
import { safeStableStringify } from "../src/canonical.js";
import { base64ToBytes, isLikelyBase64 } from "../src/encoding-utils.js";
import { getHandshakeConfig } from "../src/config.js";
import { secureCompareBytes } from "../src/utils.js";

/** Input shape expected by verification with positive validation */
export type VerifyExtendedInput = {
  readonly secret: ArrayBuffer | Uint8Array | string; // server-side secret (raw or base64)
  readonly payload: unknown; // same canonicalization as client
  readonly nonce: string; // base64-encoded nonce from client
  readonly timestamp: number; // unix timestamp in milliseconds
  readonly signatureBase64: string; // base64-encoded HMAC signature
  readonly method?: string; // HTTP method (if binding to request)
  readonly path?: string; // HTTP path (if binding to request)
  readonly bodyHash?: string; // SHA-256 base64 hash of request body
  readonly kid?: string; // key identifier for multi-key scenarios
};

// Configuration constants
const DEFAULT_SKEW_MS = 120_000; // 2 minutes — conservative default
const NONCE_TTL_MS = 300_000; // 5 minutes — shorter replay window by default

// Precompiled regex patterns for performance
const METHOD_RE = /^[A-Z]+$/;
const KID_RE = /^[\w.-]+$/;

// Security limits
const MAX_SIGNATURE_LENGTH = 512;
const MAX_PATH_LENGTH = 2048;
const MAX_METHOD_LENGTH = 20;
const MIN_SECRET_BYTES = 32; // L3 security posture requires >= 32 bytes
const MAX_SECRET_BYTES = 4096;
// Bound the canonical message size to mitigate DoS via oversized inputs
// This limit covers the framed canonical string: `${ts}.${nonce}.${method}.${path}.${bodyHash}.${payload}.${kid}`
// Adjust carefully if legitimate use cases require larger messages.
const MAX_CANONICAL_BYTES = 64 * 1024; // 64 KiB

/**
 * Interface for nonce storage backends.
 * SECURITY REQUIREMENT: Implementations MUST be atomic and distributed-safe
 * for production deployments with multiple server instances.
 */
export interface INonceStore {
  /**
   * Check if a nonce has been used before.
   *
   * WARNING: This method alone is NOT safe for distributed systems due to race conditions.
   * Use in combination with store() OR implement atomic storeIfNotExists().
   *
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to check
   * @returns Promise resolving to true if nonce exists (already used)
   */
  has(kid: string, nonce: string): Promise<boolean>;

  /**
   * Store a nonce with expiration.
   *
   * WARNING: If used after has(), creates a race condition window in distributed systems.
   * For production, implement atomic storeIfNotExists() instead.
   *
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to store
   * @param ttlMs - Time-to-live in milliseconds
   */
  store(kid: string, nonce: string, ttlMs: number): Promise<void>;

  /**
   * Atomically store nonce if it does not exist (e.g., Redis SET NX PX).
   * Returns true if stored (reserved), false if the nonce already exists.
   *
   * PRODUCTION RECOMMENDATION: Implement this method for replay-safe verification.
   *
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to store
   * @param ttlMs - Time-to-live in milliseconds
   * @returns Promise resolving to true if nonce was stored, false if already exists
   */
  storeIfNotExists?(
    kid: string,
    nonce: string,
    ttlMs: number,
  ): Promise<boolean>;

  /**
   * Optional: reserve a nonce with a short TTL to mitigate DoS from bogus signatures.
   * Returns true if reserved, false if already exists.
   */
  reserve?(kid: string, nonce: string, reserveTtlMs: number): Promise<boolean>;
  /**
   * Optional: finalize a reserved nonce by extending TTL to the full window.
   */
  finalize?(kid: string, nonce: string, ttlMs: number): Promise<void>;
  /**
   * Optional: delete a reserved nonce (for cleanup on failed verifications).
   *
   * @param kid - Key identifier for namespacing
   * @param nonce - The nonce value to delete
   */
  delete?(kid: string, nonce: string): Promise<void>;

  /**
   * Optional cleanup method for expired entries.
   * Implementations should call this periodically to prevent unbounded growth.
   */
  cleanup?(): Promise<void>;
}

/**
 * Example (NOT FOR PRODUCTION) in-memory nonce store.
 *
 * ⚠️ PRODUCTION WARNING: This implementation is NOT suitable for production:
 * - Not distributed: works only with single server instance
 * - Not persistent: lost on restart
 * - Not atomic: race conditions possible with high concurrency
 *
 * For production, use Redis, DynamoDB, or another distributed store.
 */
/* eslint-disable functional/immutable-data -- Justification: In-memory store intentionally mutates a private Map to track nonces and expirations. This non-production helper encapsulates Map#set/delete as part of its contract. */
export class InMemoryNonceStore implements INonceStore {
  #map = new Map<string, number>(); // key = `${kid}:${nonce}`, value = expiry unix ms

  async has(kid: string, nonce: string): Promise<boolean> {
    this.#validateStoreParams(kid, nonce);
    const key = `${kid}:${nonce}`;
    const now = Date.now();
    const exp = this.#map.get(key);
    if (typeof exp === "number" && exp > now) return true;
    if (typeof exp === "number" && exp <= now) this.#map.delete(key);
    return false;
  }

  async store(kid: string, nonce: string, ttlMs: number): Promise<void> {
    this.#validateStoreParams(kid, nonce);
    if (typeof ttlMs !== "number" || ttlMs < 1 || ttlMs > 86400000) {
      throw new InvalidParameterError("ttlMs must be between 1 and 86400000");
    }
    const key = `${kid}:${nonce}`;
    const exp = Date.now() + Math.max(0, Math.floor(ttlMs));
    this.#map.set(key, exp);
  }

  async storeIfNotExists(
    kid: string,
    nonce: string,
    ttlMs: number,
  ): Promise<boolean> {
    this.#validateStoreParams(kid, nonce);
    if (typeof ttlMs !== "number" || ttlMs < 1 || ttlMs > 86400000) {
      throw new InvalidParameterError("ttlMs must be between 1 and 86400000");
    }
    const key = `${kid}:${nonce}`;
    const now = Date.now();
    const existing = this.#map.get(key);
    if (typeof existing === "number" && existing > now) return false;
    const exp = now + Math.max(0, Math.floor(ttlMs));
    this.#map.set(key, exp);
    return true;
  }

  async delete(kid: string, nonce: string): Promise<void> {
    this.#validateStoreParams(kid, nonce);
    const key = `${kid}:${nonce}`;
    this.#map.delete(key);
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [k, exp] of this.#map.entries()) {
      if (exp <= now) this.#map.delete(k);
    }
  }

  #validateStoreParams(kid: string, nonce: string): void {
    if (typeof kid !== "string" || kid.length === 0 || kid.length > 128) {
      throw new InvalidParameterError("kid must be a non-empty string");
    }
    if (typeof nonce !== "string" || nonce.length === 0) {
      throw new InvalidParameterError("nonce must be a non-empty string");
    }

    const cfg = getHandshakeConfig();
    const maxLen =
      typeof cfg.handshakeMaxNonceLength === "number"
        ? cfg.handshakeMaxNonceLength
        : 256;
    const allowedFormats =
      Array.isArray(cfg.allowedNonceFormats) &&
      cfg.allowedNonceFormats.length > 0
        ? cfg.allowedNonceFormats
        : ["base64", "base64url"];

    if (nonce.length > maxLen) {
      throw new InvalidParameterError("nonce must be a non-empty string");
    }

    const allowed = (() => {
      if (
        (allowedFormats.includes("base64") ||
          allowedFormats.includes("base64url")) &&
        isLikelyBase64(nonce)
      )
        return true;
      if (allowedFormats.includes("hex") && /^[0-9a-f]+$/i.test(nonce))
        return true;
      return false;
    })();

    if (!allowed) {
      throw new InvalidParameterError(
        "nonce must be in an allowed encoded format",
      );
    }
  }
}
/* eslint-enable functional/immutable-data */

// Input validation with positive validation (allowlist approach)
function validateVerifyInput(input: VerifyExtendedInput): void {
  if (!input || typeof input !== "object") {
    throw new InvalidParameterError("Invalid input object");
  }
  validateSecret(input.secret);
  validateNonce(input.nonce);
  validateTimestamp(input.timestamp);
  validatePayload(input.payload);
  validateSignature(input.signatureBase64);
  if (input.method !== undefined) validateMethod(input.method);
  if (input.path !== undefined) validatePath(input.path);
  if (input.bodyHash !== undefined) validateBodyHash(input.bodyHash);
  if (input.kid !== undefined) validateKid(input.kid);
}

function validateSecret(
  secret: ArrayBuffer | Uint8Array | string | undefined,
): void {
  if (!secret) {
    throw new InvalidParameterError("Missing secret");
  }
  if (typeof secret === "string") {
    if (secret.length === 0 || secret.length > 1024) {
      throw new InvalidParameterError("Invalid secret length");
    }
  } else if (secret instanceof ArrayBuffer) {
    if (secret.byteLength === 0 || secret.byteLength > MAX_SECRET_BYTES) {
      throw new InvalidParameterError("Invalid secret buffer length");
    }
  } else if (ArrayBuffer.isView(secret)) {
    // Enforce by byteLength across all ArrayBufferViews (TypedArray/DataView)
    const len = (secret as ArrayBufferView).byteLength;
    if (len < MIN_SECRET_BYTES || len > MAX_SECRET_BYTES) {
      throw new InvalidParameterError("Invalid secret array length");
    }
  } else {
    throw new InvalidParameterError(
      "Secret must be string, ArrayBuffer, or Uint8Array",
    );
  }
}

function validateNonce(nonce: unknown): void {
  if (typeof nonce !== "string" || nonce.length === 0) {
    throw new InvalidParameterError("nonce must be a non-empty string");
  }
  try {
    const cfg = getHandshakeConfig();
    const maxLen =
      typeof cfg.handshakeMaxNonceLength === "number"
        ? cfg.handshakeMaxNonceLength
        : 256;
    const allowedFormats =
      Array.isArray(cfg.allowedNonceFormats) &&
      cfg.allowedNonceFormats.length > 0
        ? cfg.allowedNonceFormats
        : ["base64", "base64url"];

    if (nonce.length > maxLen) {
      throw new InvalidParameterError("nonce too long");
    }

    const isAllowed =
      ((allowedFormats.includes("base64") ||
        allowedFormats.includes("base64url")) &&
        isLikelyBase64(nonce)) ||
      (allowedFormats.includes("hex") && /^[0-9a-f]+$/i.test(nonce));

    if (!isAllowed) {
      throw new InvalidParameterError("nonce is not in an allowed format");
    }
  } catch (err) {
    if (err instanceof InvalidParameterError) throw err;
    throw new InvalidParameterError("Invalid nonce");
  }
}

function validateTimestamp(timestamp: unknown): void {
  if (typeof timestamp !== "number") {
    throw new InvalidParameterError("Invalid timestamp");
  }
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    throw new InvalidParameterError("timestamp out of reasonable range");
  }
}

function validatePayload(payload: unknown): void {
  try {
    if (typeof payload === "string") {
      const max = 10 * 1024 * 1024; // 10 MB
      if (payload.length > max) {
        throw new InvalidParameterError("payload too large");
      }
    } else if (payload !== undefined && payload !== null) {
      const s = safeStableStringify(payload);
      const max = 10 * 1024 * 1024; // 10 MB
      if (s.length > max) {
        throw new InvalidParameterError("payload too large");
      }
    }
  } catch (err) {
    if (err instanceof InvalidParameterError) throw err;
    throw new InvalidParameterError("Invalid payload");
  }
}

function validateSignature(signatureBase64: unknown): void {
  if (typeof signatureBase64 !== "string" || signatureBase64.length === 0) {
    throw new InvalidParameterError(
      "signatureBase64 must be a non-empty string",
    );
  }
  if (signatureBase64.length > MAX_SIGNATURE_LENGTH) {
    throw new InvalidParameterError("Signature too long");
  }
  if (!isLikelyBase64(signatureBase64)) {
    throw new InvalidParameterError(
      "signatureBase64 must be base64 or base64url",
    );
  }
}

function validateMethod(method: unknown): void {
  if (typeof method !== "string" || method.length > MAX_METHOD_LENGTH) {
    throw new InvalidParameterError("Invalid method");
  }
  if (!METHOD_RE.test(method.toUpperCase())) {
    throw new InvalidParameterError("method must be a valid HTTP method");
  }
}

function validatePath(path: unknown): void {
  if (typeof path !== "string" || path.length > MAX_PATH_LENGTH) {
    throw new InvalidParameterError("Invalid path");
  }
  if (!path.startsWith("/")) {
    throw new InvalidParameterError("path must start with '/'");
  }
  if (path.includes("..") || path.includes("//")) {
    throw new InvalidParameterError("path traversal patterns are not allowed");
  }
}

function validateBodyHash(bodyHash: unknown): void {
  if (typeof bodyHash !== "string" || bodyHash.length > 256) {
    throw new InvalidParameterError("Invalid bodyHash");
  }
  if (bodyHash.length > 0 && !isLikelyBase64(bodyHash)) {
    throw new InvalidParameterError("bodyHash must be base64 or base64url");
  }
}

function validateKid(kid: unknown): void {
  if (typeof kid !== "string" || kid.length === 0 || kid.length > 128) {
    throw new InvalidParameterError("Invalid kid");
  }
  if (!KID_RE.test(kid)) {
    throw new InvalidParameterError("kid contains invalid characters");
  }
}

// Normalize secret to Uint8Array for HMAC operations
function normalizeSecret(
  secret: ArrayBuffer | Uint8Array | string,
): Uint8Array {
  if (typeof secret === "string") {
    // If it looks like base64, decode; otherwise treat as UTF-8
    if (isLikelyBase64(secret)) {
      return base64ToBytes(secret);
    }
    return SHARED_ENCODER.encode(secret);
  }
  if (secret instanceof ArrayBuffer) {
    return new Uint8Array(secret);
  }
  if (ArrayBuffer.isView(secret)) {
    return new Uint8Array(secret.buffer, secret.byteOffset, secret.byteLength);
  }
  throw new InvalidParameterError("Unsupported secret type");
}

// Use shared constant-time compare for bytes from core utils.
// This provides a unified implementation with a minimum timing floor.

// Note: bytesToBase64 helper is provided by src/encoding-utils and imported above.

// Compute HMAC-SHA256 (cross-platform, ESM-safe)
async function computeHmacSha256(
  keyBytes: Uint8Array,
  messageBytes: Uint8Array,
): Promise<Uint8Array> {
  const subtle = (
    globalThis as unknown as { crypto?: { subtle?: SubtleCrypto } }
  ).crypto?.subtle;
  if (subtle) {
    // Copy into fresh buffers to satisfy typed array semantics
    const keyCopy = new Uint8Array(keyBytes.length);
    keyCopy.set(keyBytes);
    const msgCopy = new Uint8Array(messageBytes.length);
    msgCopy.set(messageBytes);
    try {
      const key = await subtle.importKey(
        "raw",
        keyCopy,
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"],
      );
      const signature = await subtle.sign("HMAC", key, msgCopy);
      return new Uint8Array(signature);
      // eslint-disable-next-line sonarjs/no-useless-catch
    } catch (err) {
      throw err;
    } finally {
      // Best-effort wipe of keyCopy
      /* eslint-disable functional/no-let, functional/immutable-data, security/detect-object-injection --
         Justification: Local secure wipe of a temporary Uint8Array. This is an isolated, in-place
         zeroization of transient key material; mutation is intentional and does not escape.
      */
      for (let i = 0; i < keyBytes.length; i++) keyCopy[i] = 0;
      /* eslint-enable functional/no-let, functional/immutable-data, security/detect-object-injection */
    }
  }

  // Node.js fallback (ESM-safe)
  try {
    const nodeCrypto = await import("node:crypto");
    const hmac = nodeCrypto.createHmac("sha256", Buffer.from(keyBytes));
    hmac.update(Buffer.from(messageBytes));
    return Uint8Array.from(hmac.digest());
  } catch {
    // Older Node alias (in case node:crypto is unavailable)
    const nodeCrypto = await import("crypto");
    const nodeCryptoMod = nodeCrypto as unknown as {
      createHmac(
        algo: "sha256",
        key: Buffer,
      ): { update(data: Buffer): void; digest(): Buffer };
    };
    const hmac = nodeCryptoMod.createHmac("sha256", Buffer.from(keyBytes));
    hmac.update(Buffer.from(messageBytes));
    return Uint8Array.from(hmac.digest());
  }
}

/**
 * Verify API request signature using shared canonicalization and atomic nonce operations.
 *
 * SECURITY FEATURES:
 * - Uses shared canonicalization (same as client) to ensure signature consistency
 * - Atomic nonce operations prevent replay attacks in distributed systems
 * - Constant-time byte comparison prevents timing attacks
 * - Comprehensive input validation with positive validation
 *
 * Throws typed errors on any failure:
 * - InvalidParameterError | TimestampError | ReplayAttackError | SignatureVerificationError | InvalidConfigurationError
 *
 * @returns Promise resolving to true if signature is valid (otherwise throws)
 */
export async function verifyApiRequestSignature(
  input: VerifyExtendedInput,
  nonceStore: INonceStore,
  options?: { maxSkewMs?: number; nonceTtlMs?: number },
): Promise<boolean> {
  // Validate inputs (throws InvalidParameterError on bad inputs)
  validateVerifyInput(input);
  if (!nonceStore) {
    throw new InvalidParameterError("nonceStore is required");
  }

  const {
    secret,
    payload,
    nonce,
    timestamp,
    signatureBase64,
    kid,
    method,
    path,
    bodyHash,
  } = input;
  const maxSkew = options?.maxSkewMs ?? DEFAULT_SKEW_MS;
  const nonceTtl = options?.nonceTtlMs ?? NONCE_TTL_MS;

  // Time window validation
  const now = Date.now();
  const skew = Math.abs(now - timestamp);
  if (skew > maxSkew) {
    throw new TimestampError("timestamp out of reasonable range");
  }

  // Normalize secret and enforce length constraints
  const keyBytes = normalizeSecret(secret);
  if (
    keyBytes.length < MIN_SECRET_BYTES ||
    keyBytes.length > MAX_SECRET_BYTES
  ) {
    throw new InvalidParameterError("Secret length is out of bounds");
  }

  // Pre-validate nonce store capability without performing any stateful operation.
  // This surfaces configuration errors deterministically and does not leak signature validity.
  if (typeof nonceStore.storeIfNotExists !== "function") {
    throw new InvalidConfigurationError(
      "NonceStore must implement storeIfNotExists() for atomic replay protection",
    );
  }

  // Shared canonicalization for payload (match client behaviour)
  const payloadString = safeStableStringify(payload);

  // Build the same canonical string as client
  const canonicalParts = [
    String(timestamp),
    nonce,
    (method ?? "").toUpperCase(),
    path ?? "",
    bodyHash ?? "",
    payloadString,
    kid ?? "",
  ];
  const canonical = canonicalParts.join(".");
  const messageBytes = SHARED_ENCODER.encode(canonical);

  // DoS hardening: bail out early on excessive canonical size
  if (messageBytes.byteLength > MAX_CANONICAL_BYTES) {
    throw new InvalidParameterError(
      `Canonical message too large (${messageBytes.byteLength} bytes)` as const,
    );
  }

  // Compute HMAC and compare in constant time (bytes) BEFORE touching the nonce store
  const mac = await computeHmacSha256(keyBytes, messageBytes);
  const sigBytes = base64ToBytes(signatureBase64);
  const equal = secureCompareBytes(mac, sigBytes);
  if (!equal) {
    // Fail closed without interacting with the nonce store
    throw new SignatureVerificationError("Signature mismatch");
  }

  // After signature verification succeeds, atomically store the nonce with full TTL
  const kidForStore = kid ?? "default";
  const stored = await nonceStore.storeIfNotExists(
    kidForStore,
    nonce,
    nonceTtl,
  );
  if (!stored) {
    // Nonce already present indicates replay
    throw new ReplayAttackError("Nonce already used or reserved");
  }

  return true;
}

// Backward compatibility alias
export { verifyApiRequestSignature as verifyApiRequestSignatureExtended };

/**
 * Safe wrapper that returns boolean without throwing typed errors.
 * Use this when you do not want verification failure reasons to leak to callers.
 */
/* eslint-disable security-node/detect-unhandled-async-errors */
export async function verifyApiRequestSignatureSafe(
  input: VerifyExtendedInput,
  nonceStore: INonceStore,
  options?: { maxSkewMs?: number; nonceTtlMs?: number },
): Promise<boolean> {
  try {
    return await verifyApiRequestSignature(input, nonceStore, options);
  } catch {
    // Intentionally ignore errors in safe wrapper - return false on any failure
    return false;
  }
}
/* eslint-enable security-node/detect-unhandled-async-errors */

/**
 * Production-friendly wrapper that retrieves the secret material via a key provider based on kid.
 * This avoids passing raw secrets per call and supports rotation.
 */
export async function verifyApiRequestSignatureWithKeyProvider(
  input: Omit<VerifyExtendedInput, "secret"> & { readonly kid: string },
  nonceStore: INonceStore,
  options: { maxSkewMs?: number; nonceTtlMs?: number } & {
    readonly keyProvider: (kid: string) => Promise<Uint8Array> | Uint8Array;
  },
): Promise<boolean> {
  const keyBytes = await options.keyProvider(input.kid);
  const extended: VerifyExtendedInput = { ...input, secret: keyBytes };
  return verifyApiRequestSignature(extended, nonceStore, options);
}
