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

/**
 * Sanitizes error objects for safe logging by truncating messages
 * and extracting only safe properties. Prevents leaking sensitive
 * user input in error messages or logs.
 *
 * @param err - The error to sanitize
 * @returns Sanitized error properties suitable for logging
 */
export function sanitizeErrorForLogs(err: unknown): {
  name?: string;
  code?: string;
  message?: string;
} {
  if (err instanceof Error) {
    const code = (err as { code?: string }).code;
    return {
      name: err.name,
      message: String(err.message || "").slice(0, 256),
      ...(code ? { code } : {}),
    };
  }
  return { message: String(err).slice(0, 256) };
}
