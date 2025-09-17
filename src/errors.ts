// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

import {
  MAX_TOTAL_STACK_LENGTH,
  MAX_STACK_LINE_LENGTH,
  MAX_PARENS_PER_LINE,
} from "./config.ts";

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

// Canonicalization specific error classes (clear taxonomy for callers)
export class CanonicalizationDepthError extends InvalidParameterError {
  public override readonly code = 'ERR_INVALID_PARAMETER' as const;
  public readonly canonicalCode = 'ERR_CANON_DEPTH' as const;
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationDepthError';
  }
}

export class CanonicalizationTraversalError extends InvalidParameterError {
  public override readonly code = 'ERR_INVALID_PARAMETER' as const;
  public readonly canonicalCode = 'ERR_CANON_TRAVERSAL' as const;
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationTraversalError';
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

export class SecurityValidationError extends InvalidParameterError {
  public override readonly code = "ERR_INVALID_PARAMETER" as const;
  public readonly securityCode = "ERR_SECURITY_VALIDATION" as const;

  constructor(
    _message: string,
    public readonly securityScore: number,
    public readonly threshold: number,
    public readonly primaryThreat: string,
    public readonly recommendation: string,
    public readonly context: string,
  ) {
    super(
      `${context}: BLOCKED - Cumulative security risk score ${securityScore}/${threshold} exceeds safety threshold. Primary threat: ${primaryThreat}. ${recommendation}`,
    );
    this.name = "SecurityValidationError";
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
      message: error.message.slice(0, 256),
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

export function getStackFingerprint(stack?: string): string | undefined {
  if (!stack) return undefined;
  try {
    // Hard caps to avoid pathological memory usage if a hostile environment feeds an
    // enormous stack string (defense in depth beyond ReDoS mitigation).
    if (stack.length > MAX_TOTAL_STACK_LENGTH) {
      stack = stack.slice(0, MAX_TOTAL_STACK_LENGTH);
    }
    // Normalize stack by stripping memory addresses, absolute paths and line numbers.
    // SECURITY: Replaced a complex regex (flagged by eslint-plugin-redos) with a
    // bounded linear-time parser to eliminate potential catastrophic backtracking.
    // The previous pattern attempted to match: "(any chars up to 256):(line):(col)".
    // We now scan characters and replace any parenthesized segment that looks like
    // a file:line:column triple where line/column are 1-6 digit numbers.
    const normalized = stack
      .split("\n")
      .map((l) => sanitizeStackLine(l).trim())
      .join("\n");
    return fnv1a32(normalized).toString(16).padStart(8, "0");
  } catch {
    return undefined;
  }
}

/**
 * Create a typed InvalidParameterError with optional context prefix.
 * Centralizes message formatting so callers can rely on errors.ts for message shape.
 */
export function makeInvalidParameterError(
  detail: string,
  context?: string,
): InvalidParameterError {
  if (typeof context === "string" && context.length > 0) {
    return new InvalidParameterError(`${context}: ${detail}`);
  }
  return new InvalidParameterError(detail);
}

/**
 * Create a CircuitBreakerError for depth budget exceeded scenarios.
 * Centralizes DoS protection error handling.
 */
export function makeDepthBudgetExceededError(
  operation: string,
  maxDepth: number,
): CanonicalizationDepthError {
  return new CanonicalizationDepthError(
    `[security-kit] ${operation}: Canonicalization depth budget exceeded (max=${maxDepth}). This prevents DoS attacks from deeply nested structures.`,
  );
}

/**
 * Create an InvalidParameterError for array/payload size violations.
 * Centralizes payload size validation error handling.
 */
export function makePayloadTooLargeError(
  operation: string,
  actualSize: number,
  maxSize: number,
): InvalidParameterError {
  return new InvalidParameterError(
    `${operation}: Payload too large (${actualSize} > ${maxSize}). This prevents DoS attacks from oversized inputs.`,
  );
}

/**
 * Sanitizes a single stack trace line by replacing segments like:
 *   (path/to/file.js:123:45)
 * or (some text:12:3) with a constant token (FILE:LINE).
 * Implementation is a single pass state machine to avoid regex backtracking.
 */
function sanitizeStackLine(line: string): string {
  // Defensive truncation of any single line to bound processing cost.
  if (line.length > MAX_STACK_LINE_LENGTH) {
    line = line.slice(0, MAX_STACK_LINE_LENGTH);
  }
  if (line.indexOf("(") === -1) return line;
  // If a line contains an excessive number of parentheses, skip normalization to avoid
  // quadratic behavior in downstream tooling or accidental expansion; hashed raw.
  const parenCount = Array.from(line).reduce(
    (count, ch) =>
      ch === "(" && count <= MAX_PARENS_PER_LINE ? count + 1 : count,
    0,
  );
  if (parenCount > MAX_PARENS_PER_LINE) return line;
  // Outer pattern: match any parenthesized chunk up to 300 safe chars (no nested parens)
  // Using a conservative upper bound eliminates runaway growth; star quantifier avoided.
  const outer = /\(([^()]{0,300})\)/g; // linear scan w/out nested quantifiers
  const innerFileLoc = /^[^):]{1,256}(?::\d{1,6}){2}$/; // anchored & bounded
  return line.replace(outer, (full, inner: string) =>
    innerFileLoc.test(inner) ? "(FILE:LINE)" : full,
  );
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
