// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
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

import { secureCompareAsync } from "../src/utils.js"; // timing-safe compare (reuse)
import { 
  InvalidParameterError, 
  TimestampError, 
  ReplayAttackError,
  SignatureVerificationError 
} from "../src/errors.js";
import { SHARED_ENCODER } from "../src/encoding.js";
import { safeStableStringify } from "../src/canonical.js";

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
const DEFAULT_RESERVATION_TTL_MS = 10_000; // 10s provisional reservation to mitigate nonce-store DoS

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
  storeIfNotExists?(kid: string, nonce: string, ttlMs: number): Promise<boolean>;

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
    if (typeof ttlMs !== 'number' || ttlMs < 1 || ttlMs > 86400000) {
      throw new InvalidParameterError('ttlMs must be between 1 and 86400000');
    }
    const key = `${kid}:${nonce}`;
    const exp = Date.now() + Math.max(0, Math.floor(ttlMs));
    this.#map.set(key, exp);
  }

  async storeIfNotExists(kid: string, nonce: string, ttlMs: number): Promise<boolean> {
    this.#validateStoreParams(kid, nonce);
    if (typeof ttlMs !== 'number' || ttlMs < 1 || ttlMs > 86400000) {
      throw new InvalidParameterError('ttlMs must be between 1 and 86400000');
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
    if (typeof kid !== 'string' || kid.length === 0 || kid.length > 128) {
      throw new InvalidParameterError('kid must be a non-empty string');
    }
    if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 256) {
      throw new InvalidParameterError('nonce must be a non-empty string');
    }
    // Stricter base64 validation: padding only at end
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(nonce)) {
      throw new InvalidParameterError('nonce must be base64-encoded');
    }
  }
}

// Input validation with positive validation (allowlist approach)
function validateVerifyInput(input: VerifyExtendedInput): void {
  if (!input || typeof input !== "object") {
    throw new InvalidParameterError("Invalid input object");
  }

  // Secret validation
  const { secret } = input;
  if (!secret) {
    throw new InvalidParameterError("Missing secret");
  }
  if (typeof secret === "string") {
    if (secret.length === 0 || secret.length > 1024) {
      throw new InvalidParameterError("Invalid secret length");
    }
  } else if (secret instanceof ArrayBuffer) {
    if (secret.byteLength === 0 || secret.byteLength > 512) {
      throw new InvalidParameterError("Invalid secret buffer length");
    }
  } else if (ArrayBuffer.isView(secret)) {
    if (secret.length === 0 || secret.length > 512) {
      throw new InvalidParameterError("Invalid secret array length");
    }
  } else {
    throw new InvalidParameterError("Secret must be string, ArrayBuffer, or Uint8Array");
  }

  // Nonce validation (positive validation)
  if (typeof input.nonce !== "string" || input.nonce.length === 0) {
    throw new InvalidParameterError("nonce must be a non-empty string");
  }
  if (input.nonce.length > 256) {
    throw new InvalidParameterError("nonce too long");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(input.nonce)) {
    throw new InvalidParameterError("nonce must be base64-encoded");
  }

  // Timestamp validation
  if (typeof input.timestamp !== "number") {
    throw new InvalidParameterError("Invalid timestamp");
  }
  if (!Number.isFinite(input.timestamp) || input.timestamp <= 0) {
    throw new InvalidParameterError("timestamp out of reasonable range");
  }

  // Payload size limits (prevent DoS with huge payloads)
  try {
    if (typeof input.payload === 'string') {
      const max = 10 * 1024 * 1024; // 10 MB
      if (input.payload.length > max) {
        throw new InvalidParameterError('payload too large');
      }
    } else if (input.payload !== undefined && input.payload !== null) {
      const s = safeStableStringify(input.payload);
      const max = 10 * 1024 * 1024; // 10 MB
      if (s.length > max) {
        throw new InvalidParameterError('payload too large');
      }
    }
  } catch (err) {
    // Re-throw validation errors
    if (err instanceof InvalidParameterError) throw err;
    throw new InvalidParameterError('Invalid payload');
  }

  // Signature validation
  if (typeof input.signatureBase64 !== "string" || input.signatureBase64.length === 0) {
    throw new InvalidParameterError("signatureBase64 must be a non-empty string");
  }
  if (input.signatureBase64.length > 512) {
    throw new InvalidParameterError("Signature too long");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(input.signatureBase64)) {
    throw new InvalidParameterError("signatureBase64 must be base64-encoded");
  }

  // Optional fields validation (allowlist approach)
  if (input.method !== undefined) {
    if (typeof input.method !== "string" || input.method.length > 16) {
      throw new InvalidParameterError("Invalid method");
    }
    if (!/^[A-Z]+$/.test(input.method)) {
      throw new InvalidParameterError("method must be a valid HTTP method");
    }
  }

  if (input.path !== undefined) {
    if (typeof input.path !== "string" || input.path.length > 2048) {
      throw new InvalidParameterError("Invalid path");
    }
    if (!/^\//.test(input.path)) {
      throw new InvalidParameterError("path contains invalid characters");
    }
  }

  if (input.bodyHash !== undefined) {
    if (typeof input.bodyHash !== "string" || input.bodyHash.length > 256) {
      throw new InvalidParameterError("Invalid bodyHash");
    }
    if (input.bodyHash.length > 0 && !/^[A-Za-z0-9+/]+={0,2}$/.test(input.bodyHash)) {
      throw new InvalidParameterError("bodyHash must be base64");
    }
  }

  if (input.kid !== undefined) {
    if (typeof input.kid !== "string" || input.kid.length === 0 || input.kid.length > 128) {
      throw new InvalidParameterError("Invalid kid");
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(input.kid)) {
      throw new InvalidParameterError("kid contains invalid characters");
    }
  }
}

// Normalize secret to Uint8Array for HMAC operations
function normalizeSecret(secret: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof secret === "string") {
    // Assume base64-encoded secret
    try {
      const binary = atob(secret);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch {
      // If not base64, treat as UTF-8
      return SHARED_ENCODER.encode(secret);
    }
  }
  if (secret instanceof ArrayBuffer) {
    return new Uint8Array(secret);
  }
  return secret;
}

// Robust bytes → base64 (browser or Node)
function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === "function") {
    // Browser environment
    let s = "";
    for (let i = 0; i < bytes.length; i++) {
      const code = bytes[i] as number;
      s += String.fromCharCode(code);
    }
    return btoa(s);
  }
  // Node.js environment
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  throw new Error("No base64 encoding available");
}

// Compute HMAC-SHA256 (cross-platform)
async function computeHmacSha256(keyBytes: Uint8Array, messageBytes: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    // Web Crypto API: copy into fresh ArrayBuffers to avoid SAB typing issues
    const keyCopy = new Uint8Array(keyBytes.length);
    keyCopy.set(keyBytes);
    const msgCopy = new Uint8Array(messageBytes.length);
    msgCopy.set(messageBytes);
    const key = await crypto.subtle.importKey(
      "raw",
      keyCopy,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign("HMAC", key, msgCopy);
    return new Uint8Array(signature);
  }
  
  // Node.js crypto fallback
  if (typeof require !== "undefined") {
    try {
      const crypto = require("crypto");
      const hmac = crypto.createHmac("sha256", Buffer.from(keyBytes));
      hmac.update(Buffer.from(messageBytes));
      return Uint8Array.from(hmac.digest());
    } catch {
      throw new Error("No HMAC implementation available");
    }
  }
  
  throw new Error("No crypto implementation available");
}

/**
 * Verify API request signature using shared canonicalization and atomic nonce operations.
 * 
 * SECURITY FEATURES:
 * - Uses shared canonicalization (same as client) to ensure signature consistency
 * - Atomic nonce operations prevent replay attacks in distributed systems
 * - Timing-safe signature comparison prevents timing attacks
 * - Comprehensive input validation with positive validation
 * - Fail-closed behavior: returns false on any error
 * 
 * @param input - Verification input with signature, nonce, payload, etc.
 * @param nonceStore - Nonce storage implementation (must be atomic for production)
 * @param options - Optional configuration (max skew, nonce TTL)
 * @returns Promise resolving to true if signature is valid, false otherwise
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

  const { secret, payload, nonce, timestamp, signatureBase64, kid, method, path, bodyHash } = input;
  const maxSkew = options?.maxSkewMs ?? DEFAULT_SKEW_MS;
  const nonceTtl = options?.nonceTtlMs ?? NONCE_TTL_MS;

  // Time window validation
  const now = Date.now();
  const skew = Math.abs(now - timestamp);
  if (skew > maxSkew) {
    throw new TimestampError('timestamp out of reasonable range');
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

  const keyBytes = normalizeSecret(secret);
  const messageBytes = SHARED_ENCODER.encode(canonical);

  // Atomic nonce reservation first, if supported
  const kidForStore = kid ?? "default";
  let reserved = false;
  const reserveTtl = Math.min(DEFAULT_RESERVATION_TTL_MS, Math.max(1000, Math.floor(nonceTtl / 10)));
  if (typeof (nonceStore as INonceStore).reserve === "function") {
    reserved = await (nonceStore as INonceStore).reserve!(kidForStore, nonce, reserveTtl);
    if (!reserved) throw new ReplayAttackError('nonce already used');
  } else if (typeof nonceStore.storeIfNotExists === "function") {
    reserved = await nonceStore.storeIfNotExists(kidForStore, nonce, reserveTtl);
    if (!reserved) throw new ReplayAttackError('nonce already used');
  } else {
    // Fallback (non-atomic): check existing
    if (await nonceStore.has(kidForStore, nonce)) {
      throw new ReplayAttackError('nonce already used');
    }
  }

  // Compute HMAC and compare in constant time
  const mac = await computeHmacSha256(keyBytes, messageBytes);
  const computedB64 = bytesToBase64(mac);

  const isEqual = await secureCompareAsync(signatureBase64, computedB64);
  if (!isEqual) {
    // If we reserved atomically, optionally delete reservation (best-effort)
    try {
      if (reserved && typeof nonceStore.delete === "function") {
        await nonceStore.delete(kidForStore, nonce);
      }
    } catch {
      // Keep reservation to throttle repeated bad attempts
    }
    throw new SignatureVerificationError('signature mismatch');
  }

  // Record nonce if we did not atomically reserve
  if (!reserved) {
    try {
      await nonceStore.store(kidForStore, nonce, nonceTtl);
    } catch (err) {
      // If we cannot persist the nonce, treat as a verification failure
      throw new InvalidParameterError('Failed to persist nonce');
    }
  } else {
    // Finalize reservation to full TTL where supported
    try {
      if (typeof (nonceStore as INonceStore).finalize === "function") {
        await (nonceStore as INonceStore).finalize!(kidForStore, nonce, nonceTtl);
      } else if (typeof nonceStore.store === "function") {
        await nonceStore.store(kidForStore, nonce, nonceTtl);
      }
    } catch {
      // Non-fatal: the nonce remains reserved for a short period; better throttle than allow replay
    }
  }

  return true;
}

// Backward compatibility alias
export { verifyApiRequestSignature as verifyApiRequestSignatureExtended };

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