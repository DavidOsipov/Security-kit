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
      ...(getStackFingerprint(err.stack)
        ? { stackHash: getStackFingerprint(err.stack) }
        : {}),
    };
  }
  return { message: String(err).slice(0, 256) };
}

// Lightweight FNV-1a 32-bit hash for stable stack fingerprinting. We avoid
// heavy crypto dependencies here to keep reporting cheap and synchronous.
function fnv1a32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = (h >>> 0) * 0x01000193;
    h = h >>> 0;
  }
  return h >>> 0;
}

export function getStackFingerprint(stack?: string | null): string | null {
  if (!stack) return null;
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
    return null;
  }
}
