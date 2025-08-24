// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Custom error classes for robust, machine-readable error handling.
 * @module
 */

export class CryptoUnavailableError extends Error {
  constructor(
    message = "A compliant Web Crypto API is not available in this environment.",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "CryptoUnavailableError";
    // Machine-friendly code for programmatic checks
    (this as unknown as { code?: string }).code = "ERR_CRYPTO_UNAVAILABLE";
  }
}

export class InvalidParameterError extends RangeError {
  constructor(message: string) {
    super(`[security-kit] ${message}`);
    this.name = "InvalidParameterError";
    (this as unknown as { code?: string }).code = "ERR_INVALID_PARAMETER";
  }
}

export class RandomGenerationError extends Error {
  constructor(
    message = "Random generation exceeded iteration safety threshold.",
  ) {
    super(`[security-kit] ${message}`);
    this.name = "RandomGenerationError";
    (this as unknown as { code?: string }).code = "ERR_RANDOM_GENERATION";
  }
}

export class InvalidConfigurationError extends Error {
  constructor(message: string) {
    super(`[security-kit] ${message}`);
    this.name = "InvalidConfigurationError";
    (this as unknown as { code?: string }).code = "ERR_INVALID_CONFIGURATION";
  }
}
