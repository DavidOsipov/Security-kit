// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Custom error classes for robust, machine-readable error handling.
 * @module
 */

export class CryptoUnavailableError extends Error {
  public readonly code = "ERR_CRYPTO_UNAVAILABLE";

  constructor(
    message = "A compliant Web Crypto API is not available in this environment.",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "CryptoUnavailableError";
  }
}

export class InvalidParameterError extends RangeError {
  public readonly code = "ERR_INVALID_PARAMETER";

  constructor(message: string) {
    super(`[security-kit] ${message}`);
    this.name = "InvalidParameterError";
  }
}

export class EncodingError extends Error {
  public readonly code = "ERR_ENCODING";

  constructor(message = "Encoding operation failed.") {
    super(`[security-kit] ${message}`);
    this.name = "EncodingError";
  }
}

export class RandomGenerationError extends Error {
  public readonly code = "ERR_RANDOM_GENERATION";

  constructor(
    message = "Random generation exceeded iteration safety threshold.",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "RandomGenerationError";
  }
}

export class InvalidConfigurationError extends Error {
  public readonly code = "ERR_INVALID_CONFIGURATION";

  constructor(message: string) {
    super(`[security-kit] ${message}`);
    this.name = "InvalidConfigurationError";
  }
}

export class SignatureVerificationError extends Error {
  public readonly code = "ERR_SIGNATURE_VERIFICATION";

  constructor(message = "Signature verification failed.") {
    super(`[security-kit] ${message}`);
    this.name = "SignatureVerificationError";
  }
}

export class ReplayAttackError extends Error {
  public readonly code = "ERR_REPLAY_ATTACK";

  constructor(message = "Potential replay attack detected.") {
    super(`[security-kit] ${message}`);
    this.name = "ReplayAttackError";
  }
}

export class TimestampError extends Error {
  public readonly code = "ERR_TIMESTAMP";

  constructor(message = "Timestamp outside acceptable window.") {
    super(`[security-kit] ${message}`);
    this.name = "TimestampError";
  }
}

export class WorkerError extends Error {
  public readonly code = "ERR_WORKER";

  constructor(message = "Worker operation failed.") {
    super(`[security-kit] ${message}`);
    this.name = "WorkerError";
  }
}

export class RateLimitError extends Error {
  public readonly code = "ERR_RATE_LIMIT";

  constructor(message = "Rate limit exceeded.") {
    super(`[security-kit] ${message}`);
    this.name = "RateLimitError";
  }
}

export class CircuitBreakerError extends Error {
  public readonly code = "ERR_CIRCUIT_BREAKER";

  constructor(message = "Circuit breaker is open due to excessive errors.") {
    super(`[security-kit] ${message}`);
    this.name = "CircuitBreakerError";
  }
}

export class TransferableNotAllowedError extends Error {
  public readonly code = "ERR_TRANSFERABLE_NOT_ALLOWED";

  constructor(
    message = "Transferable objects are not allowed unless explicitly enabled.",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "TransferableNotAllowedError";
  }
}

export class IllegalStateError extends Error {
  public readonly code = "ERR_ILLEGAL_STATE";

  constructor(message: string) {
    super(`[security-kit] ${message}`);
    this.name = "IllegalStateError";
  }
}

/**
 * Sanitizes error objects for safe logging by truncating messages
 * and extracting only safe properties. Prevents leaking sensitive
 * user input in error messages or logs.
 *
 * @param err - The error to sanitize
 * @returns Sanitized error properties suitable for logging
 */
export function sanitizeErrorForLogs(error: unknown): {
  readonly name?: string;
  readonly code?: string;
  readonly message?: string;
} {
  if (error instanceof Error) {
    const code = (error as { readonly code?: string }).code;
    return {
      name: error.name,
      message: String(error.message || "").slice(0, 256),
      ...(code ? { code } : {}),
      ...(getStackFingerprint(error.stack)
        ? { stackHash: getStackFingerprint(error.stack) }
        : {}),
    };
  }
  return { message: String(error).slice(0, 256) };
}

// Lightweight FNV-1a 32-bit hash for stable stack fingerprinting. We avoid
// heavy crypto dependencies here to keep reporting cheap and synchronous.
function fnv1a32(input: string): number {
  const initial = 0x811c9dc5 >>> 0;
  const hash = Array.from(input).reduce((accumulator, ch) => {
    // FNV-1a: xor the octet then multiply by FNV prime (0x01000193)
    const xored = (accumulator ^ ch.charCodeAt(0)) >>> 0;
    // Use Math.imul for 32-bit integer multiplication and ensure unsigned result
    return Math.imul(xored, 0x01000193) >>> 0;
  }, initial);
  return hash >>> 0;
}

export function getStackFingerprint(
  stack?: string | undefined,
): string | undefined {
  if (!stack) return undefined;
  try {
    // Normalize stack by stripping memory addresses, absolute paths and line numbers
    const normalized = stack
      .split("\n")
      .map((l) =>
        l.replace(/\([^)]{0,256}:\d{1,6}:\d{1,6}\)/g, "(FILE:LINE)").trim(),
      )
      .join("\n");
    return fnv1a32(normalized).toString(16).padStart(8, "0");
  } catch {
    return undefined;
  }
}

/**
 * Unified error class for security-kit with typed error codes.
 * Provides consistent error handling across client, worker, and server components.
 */
export class SecurityKitError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "E_INTEGRITY_REQUIRED"
      | "E_BLOB_FORBIDDEN"
      | "E_CSP_BLOCKED"
      | "E_RATE_LIMIT"
      | "E_WORKER_INIT"
      | "E_HANDSHAKE"
      | "E_TIMEOUT"
      | "E_PAYLOAD_SIZE"
      | "E_CONFIG"
      | "E_SIGNATURE_MISMATCH" = "E_CONFIG",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "SecurityKitError";
  }
}

/**
 * Branded types for type-safe string encodings.
 * These prevent accidental misuse of different base64 variants.
 */
export type Base64String = string & { readonly __brand: "base64" };
export type Base64UrlString = string & { readonly __brand: "base64url" };
