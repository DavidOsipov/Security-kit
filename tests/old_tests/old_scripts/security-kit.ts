// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
// Author Website: https://david-osipov.vision
// Author ISNI: 0000 0005 1802 960X
// Author ISNI URL: https://isni.org/isni/000000051802960X
// Author ORCID: 0009-0005-2713-9242
// Author VIAF: 139173726847611590332
// Author Wikidata: Q130604188
// Future features: "Secure & Spam-Resistant Form Handling", "Adversarial Input Fuzzing"

/**
 * Secure, performant, and modern cryptographic utilities.
 * This module provides both cryptographic primitives and safe development helpers,
 * designed to be the reference implementation for the project's Security Constitution.
 * Optimized for modern browsers with native Web Crypto API support.
 * All backward compatibility features have been removed for enhanced security and performance.
 * @module security-kit
 * @version 7.3.0
 */

// --- Custom Error Classes for Robust Handling ---
// Build-time test flag for dead code elimination of test-only exports.
// Configure your bundler (Vite/webpack/tsup) to define this as true in tests and false in production.
declare const __TEST__: boolean | undefined;

export class CryptoUnavailableError extends Error {
  constructor(
    message = "A compliant Web Crypto API is not available in this environment.",
  ) {
    super(`[secure-helpers] ${message}`);
    this.name = "CryptoUnavailableError";
    // Machine-friendly code for programmatic checks
    (this as unknown as { code?: string }).code = "ERR_CRYPTO_UNAVAILABLE";
  }
}

export class InvalidParameterError extends RangeError {
  constructor(message: string) {
    super(`[secure-helpers] ${message}`);
    this.name = "InvalidParameterError";
    (this as unknown as { code?: string }).code = "ERR_INVALID_PARAMETER";
  }
}

export class RandomGenerationError extends Error {
  constructor(
    message = "Random generation exceeded iteration safety threshold.",
  ) {
    super(`[secure-helpers] ${message}`);
    this.name = "RandomGenerationError";
    (this as unknown as { code?: string }).code = "ERR_RANDOM_GENERATION";
  }
}

// Explicit configuration error distinct from parameter range/type errors
export class InvalidConfigurationError extends Error {
  constructor(message: string) {
    super(`[secure-helpers] ${message}`);
    this.name = "InvalidConfigurationError";
    (this as unknown as { code?: string }).code = "ERR_INVALID_CONFIGURATION";
  }
}

// Centralized safe prod error reporter with token-bucket rate limiting
// Hardened: configurable burst/refill and sealed after configuration.
const _prodErrorReportState = {
  tokens: 5 as number,
  maxTokens: 5 as number,
  refillRatePerSec: 1 as number,
  lastRefillTs: 0 as number,
};

/**
 * Configures production error reporter rate-limiting. Must be called before sealing.
 * burst: allowed burst size; refillRatePerSec: sustained rate per second.
 */
export function configureErrorReporter(config: {
  burst: number;
  refillRatePerSec: number;
}): void {
  if (_cryptoState === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  const { burst, refillRatePerSec } = config;
  validateNumericParam(burst, "burst", 1, 100);
  validateNumericParam(refillRatePerSec, "refillRatePerSec", 0, 100);
  _prodErrorReportState.maxTokens = burst;
  _prodErrorReportState.tokens = burst;
  _prodErrorReportState.refillRatePerSec = refillRatePerSec;
  _prodErrorReportState.lastRefillTs = 0;
}

function _reportProdError(err: Error, context: unknown = {}) {
  try {
    if (!environment.isProduction) return;
    if (!_prodErrorHook) return;
    const now = Date.now();
    if (_prodErrorReportState.lastRefillTs === 0) {
      _prodErrorReportState.lastRefillTs = now;
    }
    const elapsedMs = now - _prodErrorReportState.lastRefillTs;
    const tokensToAdd =
      (elapsedMs / 1000) * _prodErrorReportState.refillRatePerSec;
    if (tokensToAdd > 0) {
      _prodErrorReportState.tokens = Math.min(
        _prodErrorReportState.maxTokens,
        _prodErrorReportState.tokens + tokensToAdd,
      );
      _prodErrorReportState.lastRefillTs = now;
    }
    if (_prodErrorReportState.tokens < 1) {
      return; // drop when rate-limited
    }
    _prodErrorReportState.tokens -= 1;

    const sanitized = sanitizeErrorForLogs(err) || {
      name: "Error",
      message: "Unknown",
    };
    const ctx = _redact(context);
    _prodErrorHook?.(
      new Error(`${sanitized.name}: ${sanitized.message}`),
      ctx as object,
    );
  } catch {
    // never throw from reporter
  }
}

// --- Internal Helpers and State ---

/**
 * Explicit state machine for crypto initialization lifecycle.
 *
 * State Transitions:
 * Unconfigured -> Configuring -> Configured -> Sealed
 *                     ^              |
 *                     |______________|  (via setCrypto during async init)
 */
// Replaced TypeScript enum with const object + union type to avoid Babel "strip-only" limitations in some test runners.
const CryptoState = Object.freeze({
  Unconfigured: "unconfigured",
  Configuring: "configuring",
  Configured: "configured",
  Sealed: "sealed",
} as const);
type CryptoState = (typeof CryptoState)[keyof typeof CryptoState];

let _cachedCrypto: Crypto | null = null;
let _cryptoPromise: Promise<Crypto> | null = null;
let _cryptoState: CryptoState = CryptoState.Unconfigured;
/**
 * Generation counter for async operation invalidation.
 *
 * This implements a "lease-based" pattern for handling race conditions between
 * ensureCrypto() auto-detection and explicit setCrypto() calls. When ensureCrypto()
 * starts an async operation, it captures the current generation as a "lease".
 * If setCrypto() is called during the async work, it increments this counter,
 * invalidating the lease and ensuring the explicit configuration takes precedence.
 *
 * This pattern ensures that explicit developer intent (setCrypto) always wins
 * over automatic detection, preventing race conditions without adding complexity
 * to the primary state machine.
 */
let _cryptoInitGeneration = 0; // Generation counter for async operation invalidation
let _prodErrorHook: ((error: Error, context: object) => void) | null = null;

// Test-only reset, guarded by a compile-time flag to enable DCE in production builds.
export let __test_resetCryptoStateForUnitTests: undefined | (() => void);
if (typeof __TEST__ !== "undefined" && __TEST__) {
  __test_resetCryptoStateForUnitTests = () => {
    _cachedCrypto = null;
    _cryptoPromise = null;
    _cryptoState = CryptoState.Unconfigured;
    _cryptoInitGeneration = 0;
    try {
      environment.clearCache();
    } catch {}
  };
}

/**
 * Sets a hook for reporting critical errors in production.
 * This should be connected to your application's monitoring service.
 * @param hook A function to call with the error and context.
 */
export function setProductionErrorHandler(
  hook: ((error: Error, context: object) => void) | null,
): void {
  if (_cryptoState === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  if (hook !== null && typeof hook !== "function") {
    throw new InvalidParameterError(
      "setProductionErrorHandler expects a function or null.",
    );
  }
  _prodErrorHook = hook;
}

export function setCrypto(
  cryptoLike: Crypto | null | undefined,
  { allowInProduction = false }: { allowInProduction?: boolean } = {},
): void {
  // Only prevent setting crypto when sealed - allow reconfiguration during development and testing
  if (_cryptoState === CryptoState.Sealed) {
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  }
  if (typeof allowInProduction !== "boolean") {
    throw new InvalidParameterError("allowInProduction must be a boolean.");
  }

  const isProd = environment.isProduction;
  if (isProd && cryptoLike && !allowInProduction) {
    throw new InvalidConfigurationError(
      "setCrypto() was called in production without allowInProduction=true",
    );
  }

  // Increment generation counter to invalidate any in-flight ensureCrypto() operations
  _cryptoInitGeneration++;

  // Clear any pending promise when changing crypto configuration
  _cryptoPromise = null;

  if (cryptoLike == null) {
    _cachedCrypto = null;
    _cryptoState = CryptoState.Unconfigured; // Reset to unconfigured state
    return;
  }

  // Improved validation: check that cryptoLike is an object with getRandomValues method
  if (typeof cryptoLike !== "object" || cryptoLike === null) {
    throw new InvalidParameterError(
      "setCrypto: provided value must be a Crypto object.",
    );
  }

  if (
    typeof (cryptoLike as unknown as { getRandomValues?: unknown })
      .getRandomValues !== "function"
  ) {
    throw new InvalidParameterError(
      "setCrypto: provided object must implement crypto.getRandomValues(Uint8Array).",
    );
  }

  _cachedCrypto = cryptoLike;
  _cryptoState = CryptoState.Configured; // Mark as configured with injected crypto
}

export function sealSecurityKit(): void {
  if (_cryptoState === CryptoState.Sealed) return;
  if (_cryptoState === CryptoState.Configuring) {
    throw new InvalidConfigurationError(
      "Cannot seal the security kit while initialization is in progress.",
    );
  }
  // Prevent sealing in a broken state where no crypto is available or being initialized
  if (!_cachedCrypto && !_cryptoPromise) {
    throw new CryptoUnavailableError(
      "sealSecurityKit() cannot be called before a crypto implementation is available or being initialized. Call ensureCrypto() or any async crypto function first.",
    );
  }
  _cryptoState = CryptoState.Sealed;
}

async function ensureCrypto(): Promise<Crypto> {
  // Fast path: if sealed and configured, return immediately
  if (_cryptoState === CryptoState.Sealed) {
    if (!_cachedCrypto) {
      throw new CryptoUnavailableError(
        "Security kit is sealed, but no crypto provider was configured.",
      );
    }
    return _cachedCrypto;
  }

  // If configured and we have a crypto instance, return it
  if (_cryptoState === CryptoState.Configured && _cachedCrypto) {
    return _cachedCrypto;
  }

  // If a promise is already in flight, wait for it
  if (_cryptoPromise) {
    return _cryptoPromise;
  }

  // Start the initialization process and capture the current generation
  _cryptoState = CryptoState.Configuring;
  const myGeneration = _cryptoInitGeneration; // Capture "lease" for this async operation

  _cryptoPromise = (async (): Promise<Crypto> => {
    try {
      // Check if setCrypto() was called during our async operation (generation invalidation)
      if (myGeneration !== _cryptoInitGeneration) {
        // Our operation was invalidated by an explicit setCrypto() call
        if (_cachedCrypto) {
          _cryptoState = CryptoState.Configured;
          return _cachedCrypto;
        }
        // If no crypto was set but generation changed, we were reset - start over
        _cryptoState = CryptoState.Unconfigured;
        throw new CryptoUnavailableError(
          "Crypto initialization was reset during async operation.",
        );
      }

      // If an instance was injected while we were waiting, use it
      if (_cachedCrypto) {
        _cryptoState = CryptoState.Configured;
        return _cachedCrypto;
      }

      // Try to use the global crypto object
      const globalCrypto = (globalThis as unknown as { crypto?: Crypto })
        .crypto;
      if (globalCrypto && typeof globalCrypto.getRandomValues === "function") {
        // Final generation check before committing result - prevent race condition
        if (myGeneration === _cryptoInitGeneration) {
          _cachedCrypto = globalCrypto;
          _cryptoState = CryptoState.Configured;
        }
        // Return whatever crypto instance is current (either ours or from setCrypto)
        return _cachedCrypto!;
      }

      throw new CryptoUnavailableError(
        "Web Crypto API is unavailable. In Node.js or test environments, inject an implementation via setCrypto().",
      );
    } catch (error) {
      // Only reset state if our generation is still active (we weren't invalidated)
      if (myGeneration === _cryptoInitGeneration) {
        _cryptoPromise = null;
        _cryptoState = CryptoState.Unconfigured;
      }
      throw error;
    }
  })();

  // Attach a catch handler to prevent unhandled promise rejections
  _cryptoPromise.catch((error) => {
    const safeContext = {
      component: "security-kit",
      phase: "ensureCrypto",
      message: "initialization failed",
    };
    try {
      if (environment.isProduction && _prodErrorHook) {
        _reportProdError(
          error instanceof Error ? error : new Error(String(error)),
          safeContext,
        );
      } else if (isDevelopment()) {
        secureDevLog(
          "error",
          "security-kit",
          "ensureCrypto initialization failed",
          {
            error:
              error instanceof Error
                ? { name: error.name, message: error.message }
                : String(error),
          },
        );
      }
    } catch {
      // Swallow in-reporting errors to avoid masking the original failure path.
    }
  });

  return await _cryptoPromise;
}

function ensureCryptoSync(): Crypto {
  if (_cachedCrypto) return _cachedCrypto;

  if (_cryptoState === CryptoState.Sealed) {
    throw new CryptoUnavailableError(
      "Security kit is sealed, but no crypto provider was configured.",
    );
  }

  if (_cryptoState === CryptoState.Configuring) {
    throw new CryptoUnavailableError(
      "Crypto initialization is in progress. Use the async ensureCrypto() instead.",
    );
  }

  const globalCrypto = (globalThis as unknown as { crypto?: Crypto }).crypto;
  if (globalCrypto && typeof globalCrypto.getRandomValues === "function") {
    _cachedCrypto = globalCrypto;
    _cryptoState = CryptoState.Configured;
    return _cachedCrypto;
  }

  throw new CryptoUnavailableError(
    "Web Crypto API is unavailable synchronously.",
  );
}

function validateNumericParam(
  value: number,
  paramName: string,
  min: number,
  max: number,
): void {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  ) {
    throw new InvalidParameterError(
      `${paramName} must be an integer between ${min} and ${max}.`,
    );
  }
}

function validateProbability(probability: number): void {
  if (
    typeof probability !== "number" ||
    !(probability >= 0 && probability <= 1)
  ) {
    throw new InvalidParameterError(
      `Probability must be a number between 0 and 1.`,
    );
  }
}

// --- Public API ---

/**
 * A URL-friendly alphabet used by default in nanoid.
 * Consists of 64 characters: A-Z, a-z, 0-9, _, -
 * Note: This specific order is chosen to avoid issues with auto-select on double-click.
 */
export const URL_ALPHABET =
  "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

/**
 * Hexadecimal alphabet for generating hex-based IDs.
 * Consists of 16 characters: 0-9, a-f
 */
const HEX_ALPHABET = "0123456789abcdef";

export function getSecureRandomBytesSync(length = 1): Uint8Array {
  validateNumericParam(length, "length", 1, 4096);
  const crypto = ensureCryptoSync();
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Generates a cryptographically secure, random string from a given alphabet.
 *
 * This function is inspired by nanoid's implementation and incorporates two key security
 * and performance principles from the Security Constitution:
 *
 * 1.  **Cryptographic Integrity (MUST):** It uses rejection sampling to ensure a uniform,
 *     unbiased distribution of characters for any alphabet size, preventing modulo bias.
 * 2.  **Performance is a Security Feature (1.6):** It detects when the alphabet size is a
 *     power of two and uses a highly optimized bitmasking approach for maximum performance.
 *
 * Security Features:
 * - Uses rejection sampling to eliminate modulo bias (critical for security)
 * - Automatically optimizes for power-of-two alphabet sizes with bitmasking
 * - Validates all inputs to prevent invalid configurations
 * - Uses secure random bytes from Web Crypto API
 * - Fails loudly on invalid parameters per Constitution principle 1.4
 *
 * @param alphabet The string of unique characters to use for generation. Must be 1-256 chars.
 * @param size The desired length of the output string. Must be 1-1024 chars.
 * @returns A secure, randomly generated string.
 * @throws InvalidParameterError if parameters are out of range or alphabet is invalid.
 */
/*
 * The following function, `generateSecureStringSync`, is a direct adaptation of
 * the core logic from `nanoid` (https://github.com/ai/nanoid), which is
 * licensed under the MIT license.
 *
 * nanoid copyright:
 * Copyright 2017-present Andrey Sitnik and contributors <https://sitnik.ru/>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
export function generateSecureStringSync(
  alphabet: string,
  size: number,
): string {
  validateNumericParam(size, "size", 1, 1024);
  if (
    typeof alphabet !== "string" ||
    alphabet.length === 0 ||
    alphabet.length > 256
  ) {
    throw new InvalidParameterError(
      "Alphabet must be a string with 1 to 256 characters.",
    );
  }

  // Validate alphabet for uniqueness (prevent subtle bugs from duplicate characters)
  const uniqueChars = new Set(alphabet);
  if (uniqueChars.size !== alphabet.length) {
    throw new InvalidParameterError(
      "Alphabet must contain only unique characters.",
    );
  }

  // --- nanoid's Bitmasking Optimization ---
  // For alphabet sizes that are powers of 2, we can use fast bitmasking.
  // For other sizes, we use rejection sampling to ensure uniform distribution.
  const len = alphabet.length;

  // Fast-path for single-character alphabets: simply repeat the character.
  // This avoids mask=0 and zero-step allocations which can lead to infinite loops
  // in the rejection-sampling loop for pathological inputs (e.g., len === 1).
  if (len === 1) {
    return alphabet.repeat(size);
  }

  // Calculate mask: compute the next power-of-two for len and form mask = (2^bits)-1.
  // This is clearer and avoids bit-trick edge cases.
  const bits = Math.ceil(Math.log2(Math.max(1, len)));
  const mask = (1 << bits) - 1;

  // Hardened DoS guard: fail-fast for highly inefficient rejection-sampling setups.
  // Acceptance ratio for masked bytes is len / (mask+1). If expected rejections per acceptance
  // are excessively high, abort to protect the main thread per Constitution 1.6.
  const acceptanceRatio = len / (mask + 1);
  const MAX_REJECTION_RATIO = 30; // allow up to 30 rejections per acceptance
  if (acceptanceRatio > 0 && 1 / acceptanceRatio > MAX_REJECTION_RATIO) {
    throw new InvalidParameterError(
      `Alphabet size ${len} is inefficient for uniform sampling (expected rejection ratio > ${MAX_REJECTION_RATIO}). Choose a size closer to a power of two.`,
    );
  }

  // Calculate step size: how many random bytes to request per iteration.
  // Use the empirical factor from nanoid but ensure the value is safe before allocating.
  const rawStep = Math.ceil((1.6 * mask * size) / len);
  const MAX_STEP = 4096;
  const step = Math.min(rawStep, MAX_STEP);

  if (rawStep > MAX_STEP) {
    throw new InvalidParameterError(
      "Combination of alphabet size and string length requires too many random bytes per iteration.",
    );
  }

  let id = "";
  const crypto = ensureCryptoSync();
  const bytes = new Uint8Array(step);
  const maxIterations = 1000; // Circuit breaker to prevent infinite loops
  let iterations = 0;

  try {
    while (true) {
      if (iterations++ > maxIterations) {
        throw new RandomGenerationError(
          "Failed to generate secure string within iteration limit.",
        );
      }

      crypto.getRandomValues(bytes);

      for (let i = 0; i < step; i++) {
        // This is the core of the algorithm: apply mask and check bounds
        // eslint-disable-next-line security/detect-object-injection
        const charIndex = (bytes[i] as number) & mask;

        // Rejection sampling: only accept if within alphabet bounds
        // For power-of-two sizes, this condition is always true after masking
        if (charIndex < len) {
          // eslint-disable-next-line security/detect-object-injection
          id += alphabet[charIndex] as string;
          if (id.length === size) {
            return id;
          }
        }
        // If charIndex >= len, we reject this byte and continue (rejection sampling)
      }
    }
  } finally {
    // Secure cleanup of random bytes per Constitution security practices
    secureWipe(bytes);
  }
}

export async function generateSecureId(length = 64): Promise<string> {
  validateNumericParam(length, "length", 1, 256);
  // Ensure crypto is available, then use the optimized sync implementation
  // This follows the "Separation of Pure Logic from Impure Actions" principle
  await ensureCrypto();
  return generateSecureStringSync(HEX_ALPHABET, length);
}

export function generateSecureIdSync(length = 64): string {
  // This function now becomes a simple, clear wrapper around the more powerful core function.
  // It adheres to the "Separation of Pure Logic from Impure Actions" principle,
  // where the complex logic is in one place and this is just a specific use case.
  validateNumericParam(length, "length", 1, 256);
  return generateSecureStringSync(HEX_ALPHABET, length);
}

export async function generateSecureUUID(): Promise<string> {
  const crypto = await ensureCrypto();

  // Try to use crypto.randomUUID() if available
  const cryptoWithUUID = crypto as Crypto & { randomUUID?: () => string };
  if (typeof cryptoWithUUID.randomUUID === "function") {
    return cryptoWithUUID.randomUUID();
  }

  // Fallback: Generate RFC 4122 v4 UUID using crypto.getRandomValues
  const bytes = new Uint8Array(16);
  try {
    crypto.getRandomValues(bytes);

    // Set version (4) and variant bits according to RFC 4122
    // Assert that the buffer contains the expected 16 bytes. If it does not,
    // this indicates a catastrophic failure in the underlying crypto provider
    // and we must fail loudly (per Constitution: Fail Loudly, Fail Safely).
    if (bytes.length !== 16) {
      throw new CryptoUnavailableError(
        "Failed to generate sufficient random bytes for UUID (expected 16 bytes).",
      );
    }

    const byte6 = bytes[6];
    const byte8 = bytes[8];
    if (byte6 === undefined || byte8 === undefined) {
      throw new CryptoUnavailableError(
        "Failed to generate sufficient random bytes for UUID.",
      );
    }
    // Set version and variant bits after validating buffer shape
    bytes[6] = (byte6 & 0x0f) | 0x40; // Version 4
    bytes[8] = (byte8 & 0x3f) | 0x80; // Variant 10

    // Convert to hex string with proper formatting
    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}`;
  } finally {
    // Security Constitution compliance: Always wipe cryptographic material
    secureWipe(bytes);
  }
}

/**
 * Generates a cryptographically secure random integer in the range [min, max] (inclusive).
 * This function implements rejection sampling to ensure a uniform, unbiased distribution,
 * which is critical for cryptographic applications. Using a simple modulo operation
 * (`%`) would introduce bias.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4086#section-6.1.1
 * @param min The minimum integer value (inclusive).
 * @param max The maximum integer value (inclusive).
 * @returns A promise that resolves with the secure random integer.
 */
export async function getSecureRandomInt(
  min: number,
  max: number,
): Promise<number> {
  const MAX_SAFE_RANGE = Math.pow(2, 31);
  const MIN_SAFE_RANGE = -Math.pow(2, 31);

  validateNumericParam(min, "min", MIN_SAFE_RANGE, MAX_SAFE_RANGE);
  validateNumericParam(max, "max", MIN_SAFE_RANGE, MAX_SAFE_RANGE);
  if (min > max)
    throw new InvalidParameterError("min must be less than or equal to max.");

  // Edge case: if min === max, return the value immediately
  if (min === max) return min;

  const crypto = await ensureCrypto();

  // Compute range as an unsigned BigInt for correctness across sign boundaries
  const rangeBig = BigInt(max) - BigInt(min) + BigInt(1);
  if (rangeBig <= BigInt(0))
    throw new InvalidParameterError("Invalid numeric range");

  // If the range fits within 32 bits, use a 32-bit rejection-sampling approach
  // which is fast, deterministic and unbiased.
  const MAX_UINT32 = 0x100000000; // 2^32
  if (rangeBig <= BigInt(MAX_UINT32)) {
    const range = Number(rangeBig); // safe conversion: range <= 2^32
    const arr = new Uint32Array(1);
    // largest multiple of range that fits in [0, 2^32)
    const threshold = Math.floor(MAX_UINT32 / range) * range;

    let iterations = 0;
    const maxIterations = 1_000_000; // generous upper bound to avoid false-positive failures in deterministic tests

    try {
      for (;;) {
        if (++iterations > maxIterations) {
          throw new RandomGenerationError(
            "Failed to generate unbiased random integer within iteration limit.",
          );
        }
        crypto.getRandomValues(arr);
        // Defensively guard against unusual platform behavior: ensure arr[0] is a number.
        const raw = arr[0];
        if (typeof raw !== "number") {
          // In the extremely unlikely event the platform returns an unexpected value,
          // we retry the loop rather than allowing an exception from undefined access.
          continue;
        }
        const r = (raw as number) >>> 0; // ensure unsigned
        if (r < threshold) {
          // r % range is unbiased because r < threshold which is multiple of range
          const offset = r % range;
          return min + offset;
        }
      }
    } finally {
      secureWipe(arr);
    }
  }

  // For ranges > 2^32, attempt a 64-bit unbiased draw using BigUint64Array when available.
  // This supports the rare case where min/max span more than 2^32 values.
  if (typeof BigUint64Array === "undefined") {
    throw new InvalidParameterError(
      "Range too large and 64-bit random values unavailable on this platform.",
    );
  }

  const range64 = rangeBig; // BigInt
  const arr64 = new BigUint64Array(1);
  const space = BigInt(1) << BigInt(64);
  const threshold64 = space - (space % range64);

  let iterations = 0;
  const maxIterations = 1_000_000;
  try {
    for (;;) {
      if (++iterations > maxIterations) {
        throw new RandomGenerationError(
          "Failed to generate unbiased random integer within iteration limit.",
        );
      }
      crypto.getRandomValues(arr64);
      const raw = arr64[0];
      // Defensive: guard against platform oddities where arr64[0] may be undefined.
      if (typeof raw !== "bigint") {
        // If we didn't receive a BigInt, retry the loop instead of throwing.
        continue;
      }
      const r = raw as bigint;
      if (r < threshold64) {
        const mod = r % range64;
        // mod is guaranteed to be < range64 which fits into a JS Number because min/max were constrained
        return min + Number(mod);
      }
    }
  } finally {
    secureWipe(arr64);
  }
}

export async function getSecureRandomAsync(): Promise<number> {
  const crypto = await ensureCrypto();

  // Try to use BigUint64Array for 52-bit precision if available
  if (typeof BigUint64Array !== "undefined") {
    try {
      const buffer = new BigUint64Array(1);
      crypto.getRandomValues(buffer);
      const value = buffer[0];
      if (value === undefined) {
        throw new CryptoUnavailableError(
          "Failed to generate random value with BigUint64Array.",
        );
      }
      return Number(value >> BigInt(12)) / 2 ** 52;
    } catch {
      // Fall through to 32-bit fallback if BigUint64Array fails
    }
  }

  // Fallback: Use Uint32Array for 32-bit precision
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

/**
 * Generates a cryptographically secure pseudo-random floating-point number
 * in the range [0, 1) with deterministic 32-bit precision.
 *
 * ARCHITECTURAL DECISION: This synchronous function is intentionally fixed to 32-bit
 * precision for predictable performance and behavior across all environments.
 * This ensures consistent statistical properties, deterministic execution time,
 * and reliable cross-platform behavior.
 *
 * For higher precision (52-bit), use getSecureRandomAsync() which is designed
 * for asynchronous execution with platform-optimal precision detection.
 *
 * @returns A secure random number between 0 (inclusive) and 1 (exclusive)
 *          with exactly 32 bits of precision across all platforms.
 */
export function getSecureRandom(): number {
  const crypto = ensureCryptoSync();

  // ARCHITECTURAL PRINCIPLE: Deterministic 32-bit precision for predictability
  // This ensures consistent behavior, performance, and statistical properties
  // across all environments without feature detection overhead.
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export async function shouldExecuteThrottledAsync(
  probability: number,
): Promise<boolean> {
  validateProbability(probability);
  return (await getSecureRandomAsync()) < probability;
}

export function shouldExecuteThrottled(probability: number): boolean {
  validateProbability(probability);
  return getSecureRandom() < probability;
}

export const environment = (() => {
  const cache = new Map<string, boolean>();
  let explicitEnv: "development" | "production" | null = null;

  function isPrivate172(hostname: string) {
    const parts = hostname.split(".");
    if (parts.length !== 4) return false;
    const first = Number(parts[0]);
    const second = Number(parts[1]);
    return first === 172 && second >= 16 && second <= 31;
  }

  return {
    setExplicitEnv(env: "development" | "production") {
      if (_cryptoState === CryptoState.Sealed)
        throw new InvalidConfigurationError(
          "Configuration is sealed and cannot be changed.",
        );
      if (env !== "development" && env !== "production") {
        throw new InvalidParameterError(
          `Invalid environment: ${env}. Use 'development' or 'production'.`,
        );
      }
      explicitEnv = env;
      cache.clear();
    },
    get isDevelopment() {
      if (explicitEnv) return explicitEnv === "development";
      if (cache.has("isDevelopment"))
        return cache.get("isDevelopment") ?? false;
      let result = false;
      try {
        // Modern browser environment detection
        const location = (
          globalThis as unknown as { location?: { hostname?: string } }
        ).location;
        if (location) {
          const hostname = location.hostname || "";
          // Updated list with IPv6 localhost and common dev TLDs
          const devHostnames = ["localhost", "127.0.0.1", "[::1]", ""];
          const devSuffixes = [".local", ".test", ".dev"];
          const devPrefixes = ["192.168.", "10."];

          result =
            devHostnames.includes(hostname) ||
            devSuffixes.some((suffix) => hostname.endsWith(suffix)) ||
            devPrefixes.some((prefix) => hostname.startsWith(prefix)) ||
            isPrivate172(hostname);
        }
      } catch {
        /* Default to false */
      }
      cache.set("isDevelopment", result);
      return result;
    },
    get isProduction() {
      if (explicitEnv) return explicitEnv === "production";
      return !this.isDevelopment;
    },
    clearCache() {
      cache.clear();
    },
  };
})();

export function setAppEnvironment(env: "development" | "production") {
  if (_cryptoState === CryptoState.Sealed)
    throw new InvalidConfigurationError(
      "Configuration is sealed and cannot be changed.",
    );
  if (
    typeof env !== "string" ||
    (env !== "development" && env !== "production")
  ) {
    throw new InvalidParameterError(
      'Environment must be either "development" or "production".',
    );
  }
  environment.setExplicitEnv(env);
}

// CORRECTION: Export a live function instead of a static snapshot.
/**
 * Returns `true` if the current environment is determined to be 'development'.
 * This function always returns the live state and is not affected by module load order.
 */
export function isDevelopment(): boolean {
  return environment.isDevelopment;
}

// --- Secret handling utilities ---

/**
 * Performs a best-effort wipe of a TypedArray's contents by overwriting it with zeros.
 *
 * **Security Warning:** Due to the nature of JavaScript's memory management and garbage
 * collection, this function cannot guarantee that the underlying memory is securely
 * erased at a low level. The JavaScript engine may have created copies of the data
 * in memory that are inaccessible to this function.
 *
 * Its primary purpose is to prevent accidental leakage of secrets through logging,
 * debugging, or direct inspection of the buffer in developer tools. It should be
 * used as a hygienic measure, not as a guarantee of forensic-level data erasure.
 *
 * **Best Practice:** For handling secrets, prefer using non-extractable `CryptoKey`
 * objects via `createOneTimeCryptoKey` whenever possible, as this prevents the raw
 * key material from ever entering the JavaScript memory space.
 *
 * @param typedArray The ArrayBufferView (e.g., Uint8Array) to wipe.
 */
export function secureWipe(
  typedArray: ArrayBufferView | null | undefined,
): void {
  if (!typedArray) return;

  if (isDevelopment() && typedArray.byteLength > 1024) {
    secureDevLog(
      "warn",
      "secureWipe",
      "Wiping a large buffer (>1KB). For secrets, prefer using non-extractable CryptoKey objects to avoid exposing raw data to JS memory.",
    );
  }

  try {
    // Handle BigInt typed arrays explicitly (require bigint argument)
    // Note: instanceof checks guarded for environments without BigInt64Array
    if (
      typeof BigUint64Array !== "undefined" &&
      typedArray instanceof BigUint64Array
    ) {
      (typedArray as unknown as { fill: (v: bigint) => void }).fill(0n);
      (typedArray as BigUint64Array)[0];
      return;
    }
    if (
      typeof BigInt64Array !== "undefined" &&
      typedArray instanceof BigInt64Array
    ) {
      (typedArray as unknown as { fill: (v: bigint) => void }).fill(0n);
      (typedArray as BigInt64Array)[0];
      return;
    }

    // Handle other TypedArrays that have a numeric fill method
    if (
      typeof (typedArray as unknown as { fill?: unknown }).fill === "function"
    ) {
      (typedArray as unknown as { fill: (v: number) => void }).fill(0);
      (typedArray as unknown as { [key: number]: number })[0];
      return;
    }

    // Handle DataView and other ArrayBufferViews by creating a Uint8Array view
    if (
      "byteLength" in typedArray &&
      typeof typedArray.byteLength === "number"
    ) {
      const { buffer, byteOffset, byteLength } = typedArray as {
        buffer: ArrayBuffer;
        byteOffset: number;
        byteLength: number;
      };
      const view = new Uint8Array(buffer, byteOffset, byteLength);
      view.fill(0);
      view[0];
    }
  } catch {
    /* best-effort - some environments may not support certain operations */
  }
}

const MAX_COMPARISON_LENGTH = 4096;

// REMOVED: All state related to the insecure timing-vulnerable cache.

/**
 * Convert ArrayBuffer to base64 (works in Node and Browsers).
 */
function _arrayBufferToBase64(buf: ArrayBuffer): string {
  // Node.js fast-path using Buffer when available (no polyfill in browsers)
  // Using typeof avoids ReferenceError when Buffer is not defined.
  if (typeof Buffer !== "undefined" && typeof Buffer.from === "function") {
    return (
      Buffer as unknown as {
        from: (b: ArrayBuffer) => { toString: (enc: string) => string };
      }
    )
      .from(buf)
      .toString("base64");
  }

  // Portable, allocation-lean Base64 encoder for browsers and workers
  // Avoids btoa dependency and Array.from intermediate allocations.
  const bytes = new Uint8Array(buf);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const base64abc =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  const out: string[] = [];
  let i = 0;
  const l = bytes.length;
  for (; i + 2 < l; i += 3) {
    const b0 = view.getUint8(i);
    const b1 = view.getUint8(i + 1);
    const b2 = view.getUint8(i + 2);
    out.push(
      base64abc.charAt(b0 >> 2),
      base64abc.charAt(((b0 & 0x03) << 4) | (b1 >> 4)),
      base64abc.charAt(((b1 & 0x0f) << 2) | (b2 >> 6)),
      base64abc.charAt(b2 & 0x3f),
    );
  }
  if (i < l) {
    // 1 or 2 bytes remaining
    const b0 = view.getUint8(i);
    out.push(base64abc.charAt(b0 >> 2));
    if (i === l - 1) {
      out.push(base64abc.charAt((b0 & 0x03) << 4), "==");
    } else {
      const b1 = view.getUint8(i + 1);
      out.push(
        base64abc.charAt(((b0 & 0x03) << 4) | (b1 >> 4)),
        base64abc.charAt((b1 & 0x0f) << 2),
        "=",
      );
    }
  }
  return out.join("");
}

// Test-only export to validate base64 internals without exposing in production builds.
// This leverages the __TEST__ define configured in vitest.config.js and will be DCE’d in production.
export const __test_arrayBufferToBase64:
  | ((buf: ArrayBuffer) => string)
  | undefined =
  typeof __TEST__ !== "undefined" && __TEST__
    ? _arrayBufferToBase64
    : undefined;

/**
 * Sanitizes Error objects for safe logging by removing stack traces and truncating messages.
 * Prevents sensitive data from leaking through development logs.
 */
function sanitizeErrorForLogs(
  err: unknown,
): { name: string; message: string } | undefined {
  if (!(err instanceof Error)) return undefined;
  const message = err.message ? String(err.message).slice(0, 512) : "";
  return { name: err.name, message };
}

// Module-level TextEncoder reuse to avoid allocations on hot paths.
const ENCODER = new TextEncoder();

// CORRECTION: Internal test helpers are now exposed via a function that is a no-op in production.
/**
 * FOR TESTING PURPOSES ONLY.
 * Returns an object with internal helpers for testing the library's state.
 * This function will return `undefined` in production environments.
 * @returns An object with test helpers, or `undefined`.
 */
export function getInternalTestUtils():
  | {
      _getCacheKeysForTest: () => string[];
      _clearCacheForTest: () => void;
      _getCacheSizeForTest: () => number;
      _redact: (data: unknown, depth?: number) => unknown;
      _getCryptoGenerationForTest: () => number;
      _getCryptoStateForTest: () => string;
    }
  | undefined {
  // Only expose test utilities in development, test environment, or when an explicit
  // SECURITY_KIT_TEST flag is provided. This prevents accidental exposure in production builds.
  if (
    !isDevelopment() &&
    process.env["NODE_ENV"] !== "test" &&
    process.env["SECURITY_KIT_TEST"] !== "1"
  ) {
    return undefined;
  }
  // The cache has been removed, so these helpers are now stubs.
  // They are kept for API compatibility if tests rely on them.
  return {
    _getCacheKeysForTest: () => [],
    _clearCacheForTest: () => {},
    _getCacheSizeForTest: () => 0,
    _redact: (data: unknown, depth = 0) => _redact(data, depth),
    _getCryptoGenerationForTest: () => _cryptoInitGeneration,
    _getCryptoStateForTest: () => _cryptoState,
  };
}

/**
 * Performs a timing-safe comparison of two strings to prevent timing attacks
 * (OWASP A08:2021 - Software and Data Integrity Failures).
 * The function's execution time is constant, depending only on the length of the
 * longer string, not its content.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Timing_Attack_Cheat_Sheet.html
 * @param a The first string to compare.
 * @param b The second string to compare.
 * @returns True if the strings are identical, false otherwise.
 */
export function secureCompare(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  const sa = String(a ?? "").normalize("NFC");
  const sb = String(b ?? "").normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }
  const len = Math.max(sa.length, sb.length);
  // Initialize diff with the XOR of the lengths. This is the first step
  // in ensuring the comparison is not biased by length differences alone.
  let diff = sa.length ^ sb.length;
  for (let i = 0; i < len; i++) {
    const ca = sa.charCodeAt(i) || 0;
    const cb = sb.charCodeAt(i) || 0;
    // Accumulate differences using bitwise OR. This ensures the loop
    // always completes, preventing early exit that could leak timing information.
    diff |= ca ^ cb;
  }
  return diff === 0;
}

/**
 * Asynchronous constant-time string comparison using WebCrypto API.
 *
 * Provides timing-attack resistant string comparison by leveraging SHA-256 hashing
 * through SubtleCrypto. Falls back to synchronous comparison if WebCrypto is unavailable.
 *
 * REMOVED: The insecure, timing-vulnerable caching feature has been removed to enforce
 * a secure-by-default posture.
 *
 * @param a - First string to compare (nullable/undefined safe)
 * @param b - Second string to compare (nullable/undefined safe)
 * @returns Promise<boolean> - True if strings are equal, false otherwise
 * @throws InvalidParameterError - If either string exceeds MAX_COMPARISON_LENGTH
 *
 * Security: Follows OWASP Guidelines for secure string comparison.
 * Reference: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
 */
export async function secureCompareAsync(
  a: string | null | undefined,
  b: string | null | undefined,
): Promise<boolean> {
  const sa = String(a ?? "").normalize("NFC");
  const sb = String(b ?? "").normalize("NFC");
  if (sa.length > MAX_COMPARISON_LENGTH || sb.length > MAX_COMPARISON_LENGTH) {
    throw new InvalidParameterError(
      `Input length cannot exceed ${MAX_COMPARISON_LENGTH} characters.`,
    );
  }

  let cryptoLike: Crypto;
  try {
    cryptoLike = await ensureCrypto();
  } catch {
    secureDevLog(
      "warn",
      "security-kit",
      "ensureCrypto failed in secureCompareAsync; falling back to sync compare",
    );
    return secureCompare(sa, sb);
  }

  const subtle = (cryptoLike as unknown as { subtle?: unknown }).subtle as
    | SubtleCrypto
    | undefined;
  if (!subtle?.digest) {
    secureDevLog(
      "warn",
      "security-kit",
      "SubtleCrypto.digest unavailable; falling back to sync compare",
    );
    return secureCompare(sa, sb);
  }

  // The digest function is now always non-caching and secure.
  const digestFor = async (str: string): Promise<ArrayBuffer> => {
    return await subtle.digest("SHA-256", ENCODER.encode(str));
  };

  // Declare views outside try to ensure wiping in finally
  let va: Uint8Array | undefined;
  let vb: Uint8Array | undefined;
  try {
    const [da, db] = await Promise.all([digestFor(sa), digestFor(sb)]);
    va = new Uint8Array(da);
    vb = new Uint8Array(db);
    if (va.length !== vb.length) return false; // length is public
    let diff = 0;
    for (let i = 0; i < va.length; i++) {
      // eslint-disable-next-line security/detect-object-injection
      diff |= (va[i] ?? 0) ^ (vb[i] ?? 0);
    }
    return diff === 0;
  } catch (error) {
    secureDevLog(
      "error",
      "security-kit",
      "secureCompareAsync failed; falling back to sync compare",
      { error },
    );
    return secureCompare(sa, sb);
  } finally {
    // Best-effort wipe of digests per Ephemeral Secret Handling
    try {
      if (va) secureWipe(va);
    } catch {}
    try {
      if (vb) secureWipe(vb);
    } catch {}
  }
}

// CORRECTION: Hardened redaction logic.
function _redact(data: unknown, depth = 0): unknown {
  const MAX_DEPTH = 8;
  // More comprehensive regex for secret keys.
  const SECRET_KEY_REGEX =
    /token|secret|password|pass|auth|key|bearer|session|credential|jwt|signature|cookie|private|cert/i;
  // Regex for detecting JWT-like strings in values.
  const JWT_LIKE_REGEX =
    /^(eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,})$/;
  const REDACTED_VALUE = "[REDACTED]";
  const SAFE_KEY_REGEX = /^[a-zA-Z0-9_.-]{1,64}$/;

  if (depth >= MAX_DEPTH) return "[REDACTED_MAX_DEPTH]";
  if (data === null || typeof data !== "object") {
    // Redact string values that look like secrets.
    if (typeof data === "string" && JWT_LIKE_REGEX.test(data)) {
      return REDACTED_VALUE;
    }
    return data;
  }
  if (Array.isArray(data)) return data.map((item) => _redact(item, depth + 1));

  // Use a null-prototype object to prevent prototype pollution.
  const out: Record<string, unknown> = Object.create(null);

  for (const [key, rawVal] of Object.entries(data as Record<string, unknown>)) {
    // Explicitly block dangerous keys.
    if (key === "__proto__" || key === "prototype" || key === "constructor")
      continue;
    // If the key looks like a secret (e.g., contains 'token'/'password'/'key'),
    // redact it regardless of whether it passes the SAFE_KEY_REGEX. This ensures
    // that secret-like keys are not accidentally exposed through redaction.
    if (SECRET_KEY_REGEX.test(key)) {
      // eslint-disable-next-line security/detect-object-injection
      out[key] = REDACTED_VALUE;
      continue;
    }

    // For non-secret keys, only include well-formed keys to avoid leaking
    // weird or attacker-controlled property names into logs.
    if (!SAFE_KEY_REGEX.test(key)) continue;

    const next = _redact(rawVal, depth + 1);
    // eslint-disable-next-line security/detect-object-injection
    out[key] = next;
  }
  return out;
}

export function secureDevLog(
  level: "debug" | "info" | "warn" | "error",
  component: string,
  message: string,
  context: unknown = {},
): void {
  if (environment.isProduction) return;
  const safeContext = _redact(context);

  const logEntry = Object.freeze({
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    component,
    message,
    context: safeContext,
  });

  if (typeof document !== "undefined" && typeof CustomEvent !== "undefined") {
    try {
      document.dispatchEvent(
        new CustomEvent("secure-dev-log", { detail: logEntry }),
      );
    } catch {
      /* ignore */
    }
  }

  switch (level) {
    case "debug":
      console.debug(
        `[${logEntry.level}] (${component}) ${message}`,
        safeContext,
      );
      break;
    case "info":
      console.info(
        `[${logEntry.level}] (${component}) ${message}`,
        safeContext,
      );
      break;
    case "warn":
      console.warn(
        `[${logEntry.level}] (${component}) ${message}`,
        safeContext,
      );
      break;
    case "error":
      console.error(
        `[${logEntry.level}] (${component}) ${message}`,
        safeContext,
      );
      break;
    default:
      console.info(
        `[${logEntry.level}] (${component}) ${message}`,
        safeContext,
      );
  }
}

/** @deprecated Use `secureDevLog` instead. This function will be removed in a future version. */
export function secureDevNotify(
  type: "debug" | "info" | "warn" | "error",
  component: string,
  data: unknown = {},
): void {
  if (isDevelopment()) {
    console.warn(
      "[security-kit] `secureDevNotify` is deprecated and will be removed in a future version. Use `secureDevLog`.",
    );
  }
  secureDevLog(type, component, "Legacy notification", data);
}

// --- Secure URL Construction Utilities (Security Constitution Recommended) ---

/**
 * SECURITY CONSTITUTION MANDATE: Use these secure URL construction helpers
 * instead of manual string interpolation for all URL building operations.
 *
 * The native URL and URLSearchParams APIs are battle-tested and handle
 * complex encoding edge cases that manual string manipulation gets wrong.
 *
 * Constitutional Compliance:
 * - Zero Trust Architecture (1.1): Delegate to browser's hardened URL engine
 * - Fail Loudly, Fail Safely (1.4): Native APIs throw clear errors
 * - Defense in Depth (1.2): Multiple layers of validation and encoding
 */

/**
 * Creates a secure URL by safely combining a base URL with path segments and query parameters.
 * This is the RECOMMENDED approach for all URL construction to prevent encoding vulnerabilities.
 *
 * @param base - The base URL (e.g., "https://api.example.com" or "https://example.com/api/v1")
 * @param pathSegments - Optional array of path segments to append (raw, unencoded strings)
 * @param queryParams - Optional object of query parameters (raw, unencoded values)
 * @param fragment - Optional fragment/hash (raw, unencoded string)
 * @returns A properly encoded, secure URL string
 * @throws InvalidParameterError for malformed base URLs or invalid inputs
 *
 * @example
 * ```typescript
 * // Safe construction with special characters and spaces
 * const url = createSecureURL('https://api.example.com',
 *   ['users', 'search'],
 *   { q: 'John Doe', filter: 'active+premium' },
 *   'results'
 * );
 * // Returns: "https://api.example.com/users/search?q=John%20Doe&filter=active%2Bpremium#results"
 *
 * // No more manual encoding nightmares:
 * const userInput = "user input with spaces & symbols!";
 * const safeUrl = createSecureURL('https://example.com/api', ['search'], { q: userInput });
 * // Automatically and correctly encoded
 * ```
 *
 * Security: This function prevents the common vulnerability of manual string interpolation
 * by using the browser's native URL constructor and URLSearchParams APIs.
 */
export function createSecureURL(
  base: string,
  pathSegments: string[] = [],
  queryParams: Record<string, unknown> = {},
  fragment?: string,
): string {
  if (typeof base !== "string" || base.length === 0) {
    throw new InvalidParameterError("Base URL must be a non-empty string.");
  }

  let url: URL;
  try {
    url = new URL(base);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid base URL: ${base}. ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Safely append path segments using the pathname property
  if (pathSegments.length > 0) {
    for (const segment of pathSegments) {
      if (typeof segment !== "string") {
        throw new InvalidParameterError("All path segments must be strings.");
      }

      // Reject empty segments and overly long segments to reduce abuse surface
      if (segment.length === 0 || segment.length > 1024) {
        throw new InvalidParameterError(
          "Path segments must be non-empty and shorter than 1024 characters.",
        );
      }

      // Prevent path traversal via raw or percent-encoded sequences.
      // Decode any percent-encoding safely and inspect the result. This will
      // catch encoded forms like "%2e%2e" that would otherwise bypass
      // naive checks.
      let decoded: string;
      try {
        // strictDecodeURIComponentOrThrow will throw for malformed percent-encoding
        decoded = strictDecodeURIComponentOrThrow(segment);
      } catch {
        throw new InvalidParameterError(
          "Path segment contains malformed percent-encoding or control characters.",
        );
      }

      // Disallow traversal or embedded separators: only names are allowed.
      if (
        decoded === "." ||
        decoded === ".." ||
        decoded.includes("/") ||
        decoded.includes("\\") ||
        decoded.includes("..")
      ) {
        throw new InvalidParameterError(
          `Path segments must not contain path separators ('/', '\\') or navigation ('.' or '..'). Invalid segment: "${segment}"`,
        );
      }

      // Ensure the pathname ends with '/' before adding segment
      if (!url.pathname.endsWith("/")) {
        url.pathname += "/";
      }

      // Append raw segment and let the URL engine perform proper encoding.
      // The URL.pathname setter will encode characters as required; avoid
      // manual encodeURIComponent here to prevent double-encoding.
      url.pathname += segment;
    }
  }

  // Safely set query parameters using RFC3986 percent-encoding to ensure
  // spaces are encoded as %20 (not '+') and plus signs are encoded as %2B.
  if (Object.keys(queryParams).length > 0) {
    const pairs: string[] = [];
    const SAFE_KEY_REGEX = /^[a-zA-Z0-9_.-]{1,128}$/;
    for (const [key, value] of Object.entries(queryParams)) {
      if (POSTMESSAGE_FORBIDDEN_KEYS.has(key)) continue;
      if (!SAFE_KEY_REGEX.test(key)) continue;
      if (typeof key !== "string") {
        throw new InvalidParameterError(
          "Query parameter keys must be strings.",
        );
      }
      // Convert value to string safely, handling null/undefined
      const stringValue =
        value === null || value === undefined ? "" : String(value);
      // Use the project's RFC3986 encoder which is exposed as encodeQueryValue
      const encodedKey = encodeQueryValue(key);
      const encodedValue = encodeQueryValue(stringValue);
      pairs.push(`${encodedKey}=${encodedValue}`);
    }

    if (url.search && url.search.length > 1) {
      // Append to existing query string
      // url.search includes the leading '?'
      url.search += "&" + pairs.join("&");
    } else {
      url.search = "?" + pairs.join("&");
    }
  }

  // Safely set fragment
  if (fragment !== undefined) {
    if (typeof fragment !== "string") {
      throw new InvalidParameterError("Fragment must be a string.");
    }
    url.hash = fragment; // URL automatically encodes the hash
  }

  return url.href;
}

/**
 * Safely modifies an existing URL by updating its query parameters.
 * This prevents common vulnerabilities from manual query string manipulation.
 *
 * @param baseUrl - The existing URL to modify
 * @param updates - Object containing query parameter updates
 * @param options - Configuration options
 * @returns The modified URL string
 * @throws InvalidParameterError for malformed URLs
 *
 * @example
 * ```typescript
 * const original = "https://api.example.com/search?page=1&sort=name";
 * const updated = updateURLParams(original, {
 *   page: 2,
 *   filter: "user input with spaces & symbols!",
 *   sort: undefined // This will remove the 'sort' parameter
 * });
 * // Returns: "https://api.example.com/search?page=2&filter=user%20input%20with%20spaces%20%26%20symbols%21"
 * ```
 */
export function updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown>,
  options: { removeUndefined?: boolean } = {},
): string {
  const { removeUndefined = true } = options;

  if (typeof baseUrl !== "string") {
    throw new InvalidParameterError("Base URL must be a string.");
  }

  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid base URL: ${baseUrl}. ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  for (const [key, value] of Object.entries(updates)) {
    const SAFE_KEY_REGEX = /^[a-zA-Z0-9_.-]{1,128}$/;
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(key)) continue;
    if (!SAFE_KEY_REGEX.test(key)) continue;
    if (typeof key !== "string") {
      throw new InvalidParameterError("Query parameter keys must be strings.");
    }

    if (value === undefined && removeUndefined) {
      url.searchParams.delete(key);
    } else if (value === null) {
      url.searchParams.set(key, "");
    } else {
      url.searchParams.set(key, String(value));
    }
  }

  return url.href;
}

/**
 * Validates that a URL string is well-formed and optionally checks against allowlisted origins.
 *
 * @param urlString - The URL string to validate
 * @param options - Validation options
 * @returns A result object indicating success/failure
 *
 * @example
 * ```typescript
 * const result = validateURL("https://api.example.com/path?query=value");
 * if (result.ok) {
 *   console.log("Valid URL:", result.url.href);
 * } else {
 *   console.error("Invalid URL:", result.error.message);
 * }
 *
 * // With origin allowlist
 * const restrictedResult = validateURL("https://api.example.com/path", {
 *   allowedOrigins: ["https://api.example.com", "https://cdn.example.com"]
 * });
 * ```
 */
export function validateURL(
  urlString: string,
  options: {
    allowedOrigins?: string[];
    requireHTTPS?: boolean;
    maxLength?: number;
  } = {},
): { ok: true; url: URL } | { ok: false; error: Error } {
  const { allowedOrigins, requireHTTPS = false, maxLength = 2048 } = options;

  if (typeof urlString !== "string") {
    return {
      ok: false,
      error: new InvalidParameterError("URL must be a string."),
    };
  }

  if (urlString.length > maxLength) {
    return {
      ok: false,
      error: new InvalidParameterError(
        `URL length exceeds maximum of ${maxLength} characters.`,
      ),
    };
  }

  let url: URL;
  try {
    url = new URL(urlString);
  } catch (error) {
    return {
      ok: false,
      error: new InvalidParameterError(
        `Malformed URL: ${error instanceof Error ? error.message : String(error)}`,
      ),
    };
  }

  if (requireHTTPS && url.protocol !== "https:") {
    return {
      ok: false,
      error: new InvalidParameterError("URL must use HTTPS protocol."),
    };
  }

  if (allowedOrigins && allowedOrigins.length > 0) {
    if (!allowedOrigins.includes(url.origin)) {
      return {
        ok: false,
        error: new InvalidParameterError(
          `URL origin '${url.origin}' is not in the allowlist.`,
        ),
      };
    }
  }

  return { ok: true, url };
}

/**
 * Extracts and validates query parameters from a URL string.
 * Returns a safe, typed object instead of the raw URLSearchParams.
 *
 * @param urlString - The URL to parse
 * @param expectedParams - Optional schema for expected parameters
 * @returns Parsed and validated query parameters
 *
 * @example
 * ```typescript
 * const params = parseURLParams("https://example.com?page=1&filter=active&invalid=");
 * // Returns: { page: "1", filter: "active", invalid: "" }
 *
 * // With validation schema
 * const validatedParams = parseURLParams("https://example.com?page=1&count=10", {
 *   page: 'string',
 *   count: 'number'
 * });
 * ```
 */
export function parseURLParams(
  urlString: string,
  expectedParams?: Record<string, "string" | "number" | "boolean">,
): Record<string, string> {
  if (typeof urlString !== "string") {
    throw new InvalidParameterError("URL must be a string.");
  }

  let url: URL;
  try {
    url = new URL(urlString);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid URL: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Use null-prototype object to prevent prototype pollution
  const params: Record<string, string> = Object.create(null);
  // Strict allowlist for safe keys: ASCII alphanumerics plus underscore, dot, dash
  const SAFE_KEY_REGEX = /^[a-zA-Z0-9_.-]{1,128}$/;

  // Use Map for safe intermediate storage to avoid object injection
  const paramMap = new Map<string, string>();

  // Extract all parameters as strings (URLSearchParams always returns strings)
  // Use Array.from to avoid direct iterator consumption which can require downlevelIteration
  for (const [rawKey, value] of Array.from(url.searchParams.entries())) {
    // Normalize and validate key safety before assignment
    const key = String(rawKey);
    if (
      SAFE_KEY_REGEX.test(key) &&
      key !== "__proto__" &&
      key !== "constructor" &&
      key !== "prototype"
    ) {
      paramMap.set(key, value);
      // Safe assignment to null-prototype object using defineProperty
      Object.defineProperty(params, key, {
        value,
        configurable: true,
        enumerable: true,
        writable: false,
      });
    }
  }

  // Optional validation against expected schema
  if (expectedParams) {
    for (const [expectedKey, expectedType] of Object.entries(expectedParams)) {
      if (
        expectedKey === "__proto__" ||
        expectedKey === "constructor" ||
        expectedKey === "prototype"
      ) {
        continue; // Skip dangerous keys
      }

      // Safe property access using Map
      const value = paramMap.get(expectedKey);

      if (value === undefined) {
        secureDevLog(
          "warn",
          "parseURLParams",
          `Expected parameter '${expectedKey}' is missing from URL`,
          { url: urlString },
        );
        continue;
      }

      // Type validation
      if (
        expectedType === "number" &&
        (isNaN(Number(value)) || value.trim() === "")
      ) {
        secureDevLog(
          "warn",
          "parseURLParams",
          `Parameter '${expectedKey}' expected to be a number but got '${value}'`,
          { url: urlString },
        );
      } else if (
        expectedType === "boolean" &&
        !["true", "false", "1", "0"].includes(value.toLowerCase())
      ) {
        secureDevLog(
          "warn",
          "parseURLParams",
          `Parameter '${expectedKey}' expected to be a boolean but got '${value}'`,
          { url: urlString },
        );
      }
    }
  }

  return Object.freeze(params);
}

// --- Legacy URI Handling Utilities (RFC 3986) ---
//
// ⚠️  SECURITY WARNING: The functions below are for specialized use cases only.
// For 99% of URL construction needs, use the secure helpers above (createSecureURL, etc.)
//
// These RFC 3986 functions are maintained for:
// 1. Encoding single components in isolation (rare edge cases)
// 2. Stricter RFC 3986 compliance beyond browser defaults
// 3. Backward compatibility with existing code
//
// NEVER use manual string interpolation with these functions. Always prefer
// the native URL APIs through the secure helpers above.

const ENCODE_SUBDELIMS_RE = /[!'()*]/g;
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F-\u009F]/;
const _hasInvalidPercentSeq = (s: string) => /%(?![0-9A-Fa-f]{2})/.test(s);
const _splitOnEncodedOctets = (s: string) => s.split(/(%[0-9A-Fa-f]{2})/);
const _hex = (c: string) =>
  "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");

function _toStr(value: unknown): string {
  if (typeof value === "symbol") {
    throw new InvalidParameterError(
      "Cannot convert a Symbol value to a string for URI encoding.",
    );
  }
  if (value === null || typeof value === "undefined") return "";
  return String(value);
}

// Internal RFC3986-compliant encoder implementation. New code should use
// `encodeComponentRFC3986` (exported below) or the higher-level URL helpers.
function _rfc3986EncodeURIComponentImpl(
  value: unknown,
  { preservePercentEncoded = false }: { preservePercentEncoded?: boolean } = {},
): string {
  if (typeof preservePercentEncoded !== "boolean") {
    throw new InvalidParameterError(
      "preservePercentEncoded must be a boolean.",
    );
  }
  const s = _toStr(value);
  if (CONTROL_CHARS_RE.test(s)) {
    throw new InvalidParameterError(
      "Input contains forbidden control characters (CR, LF, NUL, etc.)",
    );
  }
  if (preservePercentEncoded) {
    if (_hasInvalidPercentSeq(s)) {
      throw new InvalidParameterError(
        "Malformed percent-encoding in input (preservePercentEncoded=true).",
      );
    }
    const parts = _splitOnEncodedOctets(s);
    for (let i = 0; i < parts.length; i++) {
      if (i % 2 === 0) {
        // The linter flags accessing array elements by index as an object-injection sink.
        // This is a false positive here because `i` is a numeric loop index and `parts`
        // is a local string[] created from predictable splitting. Silence the rule.
        // eslint-disable-next-line security/detect-object-injection
        const fragment = parts[i];
        if (fragment !== undefined) {
          // eslint-disable-next-line security/detect-object-injection
          parts[i] = encodeURIComponent(fragment).replace(
            ENCODE_SUBDELIMS_RE,
            _hex,
          );
        }
      }
    }
    return parts.join("");
  }
  return encodeURIComponent(s).replace(ENCODE_SUBDELIMS_RE, _hex);
}

// NOTE: The legacy `rfc3986EncodeURIComponent` wrapper has been removed.
// New code should import `encodeComponentRFC3986`, `encodeQueryValue`, or
// `encodePathSegment` depending on context.

// Preferred granular encoder for new code (non-deprecated).
export const encodeComponentRFC3986 = _rfc3986EncodeURIComponentImpl;

// Keep these named exports but point them to the non-deprecated internal impl
// so importing code doesn't receive a deprecated symbol.
export const encodePathSegment = _rfc3986EncodeURIComponentImpl;
export const encodeQueryValue = _rfc3986EncodeURIComponentImpl;

export function encodeFormValue(value: unknown): string {
  return _rfc3986EncodeURIComponentImpl(value).replace(/%20/g, "+");
}

/**
 * Helper to encode values used in `mailto:` URIs (subject/body) safely.
 * This function uses the internal RFC3986-safe encoder but is exported as
 * a supported, non-deprecated API for the specialized mailto use case.
 *
 * Note: Prefer `createSecureURL` and `updateURLParams` for HTTP(S) URLs.
 */
export function encodeMailtoValue(value: unknown): string {
  // Use the supported internal RFC3986 implementation for mailto values.
  return encodeComponentRFC3986(value);
}

export function encodeHostLabel(
  label: string,
  idnaLibrary: { toASCII: (s: string) => string },
): string {
  if (!idnaLibrary || typeof idnaLibrary.toASCII !== "function") {
    throw new InvalidParameterError(
      "An IDNA-compliant library (e.g., `punycode`) must be provided.",
    );
  }
  return idnaLibrary.toASCII(_toStr(label));
}

export function strictDecodeURIComponent(
  str: string,
  {
    onError = "return",
    replaceWith = "\uFFFD",
  }: { onError?: "return" | "replace"; replaceWith?: string } = {},
): { ok: true; value: string } | { ok: false; error: Error } {
  if (onError !== "return" && onError !== "replace") {
    throw new InvalidParameterError(
      'onError must be either "return" or "replace".',
    );
  }
  if (typeof replaceWith !== "string") {
    throw new InvalidParameterError("replaceWith must be a string.");
  }
  const s = _toStr(str);
  try {
    const decoded = decodeURIComponent(s);
    return { ok: true, value: decoded };
  } catch {
    if (onError === "replace") {
      const repaired = (() => {
        let out = "";
        for (let i = 0; i < s.length; i++) {
          const ch = s.charAt(i);
          if (ch === "%") {
            const a = s.charAt(i + 1);
            const b = s.charAt(i + 2);
            const isHex = (c: string | undefined) =>
              /[0-9A-Fa-f]/.test(c ?? "");
            if (isHex(a) && isHex(b)) {
              out += s.slice(i, i + 3);
              i += 2;
              continue;
            }
            out += replaceWith;
            if (i + 1 < s.length) i++;
            if (i + 1 < s.length) i++;
            continue;
          }
          out += ch;
        }
        return out;
      })();
      try {
        const decodedRepaired = decodeURIComponent(repaired);
        return { ok: true, value: decodedRepaired };
      } catch {
        return {
          ok: false,
          error: new InvalidParameterError("URI component is malformed"),
        };
      }
    }
    return {
      ok: false,
      error: new InvalidParameterError("URI component is malformed"),
    };
  }
}

export function strictDecodeURIComponentOrThrow(str: string): string {
  const res = strictDecodeURIComponent(str, { onError: "return" });
  if (!res.ok) {
    // Narrow the union to the error variant before throwing to satisfy TypeScript's type checker
    const err = (res as { ok: false; error: Error }).error;
    throw err;
  }
  return res.value;
}

// --- Cryptographic Key & Nonce Generation ---

// Pre-computed allowed usages set to avoid allocation on each call
const ALLOWED_KEY_USAGES = new Set([
  "encrypt",
  "decrypt",
  "wrapKey",
  "unwrapKey",
] as const);

export async function createOneTimeCryptoKey(
  options: {
    /** Key length in bits. Must be 128 or 256 for AES-GCM keys. */
    lengthBits?: 128 | 256;
    /**
     * @deprecated Use `lengthBits` for clarity. This option will be removed in a future major version.
     * Key length in bits. Must be 128 or 256 for AES-GCM keys.
     */
    length?: 128 | 256;
    usages?: Array<"encrypt" | "decrypt" | "wrapKey" | "unwrapKey">;
  } = {},
): Promise<CryptoKey> {
  const { lengthBits, usages = ["encrypt", "decrypt"] } = options;
  // Handle deprecated parameter separately to avoid TS warning
  const deprecatedLength = (options as { length?: 128 | 256 }).length;

  let bitLength: number;
  if (lengthBits !== undefined && deprecatedLength !== undefined) {
    throw new InvalidParameterError(
      "Cannot specify both lengthBits and the deprecated length. Use only lengthBits.",
    );
  }
  // Warn once per module load when deprecated option is used (dev/test only)
  if (deprecatedLength !== undefined && isDevelopment()) {
    const fn = createOneTimeCryptoKey as unknown as {
      __warnedDeprecatedLength?: boolean;
    };
    if (!fn.__warnedDeprecatedLength) {
      fn.__warnedDeprecatedLength = true;
      try {
        console.warn(
          "[security-kit] DEPRECATION: `length` is deprecated in createOneTimeCryptoKey. Use `lengthBits`. (logged once)",
        );
      } catch {}
    }
  }

  if (lengthBits !== undefined) {
    if (lengthBits !== 128 && lengthBits !== 256) {
      throw new InvalidParameterError(
        "lengthBits must be 128 or 256 for AES-GCM keys.",
      );
    }
    bitLength = lengthBits;
  } else if (deprecatedLength !== undefined) {
    if (deprecatedLength !== 128 && deprecatedLength !== 256) {
      throw new InvalidParameterError(
        "length must be 128 or 256 bits for AES-GCM keys.",
      );
    }
    bitLength = deprecatedLength;
  } else {
    bitLength = 256; // Default to 256 bits
  }

  if (
    !Array.isArray(usages) ||
    usages.length === 0 ||
    usages.some((u) => !ALLOWED_KEY_USAGES.has(u))
  ) {
    throw new InvalidParameterError(
      "usages must be a non-empty array containing only 'encrypt','decrypt','wrapKey','unwrapKey'.",
    );
  }

  const crypto = await ensureCrypto();
  const subtle = (crypto as unknown as { subtle?: unknown }).subtle as
    | SubtleCrypto
    | undefined;
  if (!subtle || (!subtle.generateKey && !subtle.importKey)) {
    throw new CryptoUnavailableError(
      "SubtleCrypto is unavailable. This feature requires a secure context.",
    );
  }

  // Enforce extractable=false per Principle of Least Privilege
  const extractable = false;

  if (typeof subtle.generateKey === "function") {
    return subtle.generateKey(
      { name: "AES-GCM", length: bitLength } as AesKeyGenParams,
      extractable,
      usages as KeyUsage[],
    );
  }

  const keyData = new Uint8Array(bitLength / 8);
  crypto.getRandomValues(keyData);
  try {
    const key = await subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM", length: bitLength } as AesKeyGenParams,
      extractable,
      usages as KeyUsage[],
    );
    return key;
  } finally {
    secureWipe(keyData);
  }
}

export function createAesGcmNonce(byteLength = 12): Uint8Array {
  validateNumericParam(byteLength, "byteLength", 12, 16);
  const crypto = ensureCryptoSync();
  const iv = new Uint8Array(byteLength);
  crypto.getRandomValues(iv);
  return iv;
}

// Minimal, explicit AES-GCM key helpers for a smaller, auditable API surface
export function createAesGcmKey128(
  usages: Array<"encrypt" | "decrypt" | "wrapKey" | "unwrapKey"> = [
    "encrypt",
    "decrypt",
  ],
): Promise<CryptoKey> {
  return createOneTimeCryptoKey({ lengthBits: 128, usages });
}

export function createAesGcmKey256(
  usages: Array<"encrypt" | "decrypt" | "wrapKey" | "unwrapKey"> = [
    "encrypt",
    "decrypt",
  ],
): Promise<CryptoKey> {
  return createOneTimeCryptoKey({ lengthBits: 256, usages });
}

// A minimal, auditable API surface exposing the most common operations.
export const SIMPLE_API = Object.freeze({
  getSecureRandomBytesSync,
  generateSecureId,
  generateSecureIdSync,
  generateSecureUUID,
  createAesGcmKey128,
  createAesGcmKey256,
  createAesGcmNonce,
  generateSRI,
  secureCompare,
  secureCompareAsync,
});

// --- Hardened Cross-Context Communication (postMessage) ---

export interface SecurePostMessageOptions {
  /** The window object to send the message to (e.g., `iframe.contentWindow`). */
  targetWindow: Window;
  /** The message payload. It will be serialized to JSON. */
  payload: unknown;
  /** The specific origin of the target window. Wildcard '*' is forbidden. */
  targetOrigin: string;
}

/**
 * Sends a message to another window context securely.
 * Implements Security Constitution Rule 2.9 by forbidding wildcard target origins.
 * @param options The secure message options.
 */
export function sendSecurePostMessage(options: SecurePostMessageOptions): void {
  const { targetWindow, payload, targetOrigin } = options;
  if (!targetWindow)
    throw new InvalidParameterError("targetWindow must be provided.");
  if (targetOrigin === "*") {
    throw new InvalidParameterError(
      "targetOrigin cannot be a wildcard ('*'). You must provide a specific origin.",
    );
  }
  if (!targetOrigin || typeof targetOrigin !== "string") {
    throw new InvalidParameterError("targetOrigin must be a specific string.");
  }

  // CORRECTION: Harden against non-serializable payloads.
  try {
    const message = JSON.stringify(payload);
    targetWindow.postMessage(message, targetOrigin);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new InvalidParameterError(
        "Payload for sendSecurePostMessage must be JSON-serializable and cannot contain circular references.",
      );
    }
    throw error; // Re-throw other unexpected errors
  }
}

export interface SecurePostMessageListener {
  /**
   * Unsubscribes the listener and cleans up resources.
   * Implements Security Constitution Rule: Event Listener Cleanup.
   */
  destroy: () => void;
}

// --- PostMessage validation helpers & constants (HARDENED) ---

/** Maximum allowed serialized payload bytes for postMessage validation. Prevents large-amplification DoS. */
export const POSTMESSAGE_MAX_PAYLOAD_BYTES = 32 * 1024; // 32 KB
/** Maximum allowed object depth when validating schema to avoid recursion DoS. */
export const POSTMESSAGE_MAX_PAYLOAD_DEPTH = 8;
/** Forbidden property keys to prevent prototype pollution attempts. */
export const POSTMESSAGE_FORBIDDEN_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

export type SchemaValue = "string" | "number" | "boolean" | "object" | "array";

/**
 * Create a short fingerprint for a payload to be safe to log. Uses SubtleCrypto when available.
 * Returns a short base64-like fingerprint (first 12 chars) or a safe fallback string.
 */
async function getPayloadFingerprint(data: unknown): Promise<string> {
  try {
    let s: string;
    try {
      s = JSON.stringify(data);
    } catch {
      return "UNSERIALIZABLE";
    }

    if (s.length > POSTMESSAGE_MAX_PAYLOAD_BYTES)
      s = s.slice(0, POSTMESSAGE_MAX_PAYLOAD_BYTES);

    // Use crypto digest if available
    try {
      const cryptoLike = await ensureCrypto();
      const subtle = (cryptoLike as unknown as { subtle?: unknown }).subtle as
        | SubtleCrypto
        | undefined;
      if (subtle && subtle.digest) {
        const digest = await subtle.digest("SHA-256", ENCODER.encode(s));
        // base64-encode and return a short prefix for logs
        const b64 = _arrayBufferToBase64(digest);
        return b64.slice(0, 12);
      }
    } catch {
      // Fall through to deterministic fallback
    }

    // Deterministic fallback: use a simple truncated hex of char codes
    let acc = 0;
    for (let i = 0; i < s.length; i++) acc = (acc * 31 + s.charCodeAt(i)) >>> 0;
    return acc.toString(16).padStart(8, "0").slice(0, 12);
  } catch {
    return "FINGERPRINT_ERR";
  }
}

/**
 * Hardened payload validator. Accepts either a function validator or a shallow schema object.
 * Returns an object describing validity and a human-readable reason for failures.
 */
export function _validatePayload(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
): { valid: boolean; reason?: string } {
  // Functions: simple try/catch wrapper so throwing validators don't break the listener
  if (typeof validator === "function") {
    try {
      const ok = (validator as (d: unknown) => boolean)(data);
      return { valid: Boolean(ok) };
    } catch (e) {
      return {
        valid: false,
        reason: `Custom validation function threw an error: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  // Schema object path: only shallow checks for performance and DoS resistance
  if (typeof data !== "object" || data === null) {
    return {
      valid: false,
      reason: `Expected an object payload but received ${typeof data}`,
    };
  }

  // Defensive copy of keys to avoid iterator mutation attacks
  const obj = data as Record<string, unknown>;
  // Detect prototype pollution where the object's prototype has been set via __proto__ literal
  const objProto = Object.getPrototypeOf(obj);
  if (objProto && objProto !== Object.prototype) {
    return {
      valid: false,
      reason:
        "Payload prototype is modified which indicates prototype-pollution attempt",
    };
  }
  const keys = Object.keys(obj);
  if (keys.length > 1024)
    return { valid: false, reason: "Payload contains too many properties." };

  // Build a safe Map of the object's own properties to avoid dynamic property access on the original object
  // (this prevents object-injection sinks flagged by static analysis while remaining performant).
  const objMap = new Map<string, unknown>(Object.entries(obj));

  // Reject payloads that attempt prototype pollution via dangerous keys
  // Explicitly check known forbidden keys to avoid any dynamic property-access sinks
  if (
    objMap.has("__proto__") ||
    objMap.has("prototype") ||
    objMap.has("constructor")
  ) {
    return {
      valid: false,
      reason: "Forbidden property name present (prototype pollution attempt)",
    };
  }

  // Reject validator definitions that explicitly declare forbidden or unsafe keys
  const SAFE_KEY_REGEX = /^[a-zA-Z0-9_.-]{1,128}$/;
  for (const fk of Object.keys(validator)) {
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(fk) || !SAFE_KEY_REGEX.test(fk)) {
      return {
        valid: false,
        reason: `Validator contains forbidden or unsafe property name: ${fk}`,
      };
    }
  }

  for (const [key, expectedType] of Object.entries(validator)) {
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(key) || !SAFE_KEY_REGEX.test(key)) {
      return {
        valid: false,
        reason: `Forbidden or unsafe property name: ${key}`,
      };
    }

    if (!objMap.has(key)) {
      return { valid: false, reason: `Missing required property '${key}'` };
    }

    // Accessing via Map.get avoids object-injection sink on bracket notation
    const value = objMap.get(key);
    const actualType = Array.isArray(value) ? "array" : typeof value;
    if (actualType !== expectedType) {
      return {
        valid: false,
        reason: `Property '${key}' has wrong type. Expected '${expectedType}' but got '${actualType}'`,
      };
    }
  }

  return { valid: true };
}

/**
 * Creates a secure listener for messages from other window contexts.
 * Implements Security Constitution Rule 2.9 by enforcing an origin allowlist.
 * @param allowedOrigins An array of specific origins that are allowed to send messages.
 * @param onMessage A callback function to execute with the parsed data from an allowed origin.
 * @returns A listener object with a `destroy` method to clean up the event listener.
 */
export type CreateSecurePostMessageListenerOptions = {
  allowedOrigins: string[];
  onMessage: (data: unknown) => void;
  /** Optional validator: either a function or a shallow schema object */
  validate?: ((d: unknown) => boolean) | Record<string, SchemaValue>;
};

export function createSecurePostMessageListener(
  allowedOrigins: string[],
  onMessage: (data: unknown) => void,
): SecurePostMessageListener;

export function createSecurePostMessageListener(
  allowedOriginsOrOptions: string[] | CreateSecurePostMessageListenerOptions,
  onMessageOptional?: (data: unknown) => void,
): SecurePostMessageListener {
  // Normalize arguments to preserve backward compatibility.
  let allowedOrigins: string[];
  let onMessage: (data: unknown) => void;
  let possibleValidator:
    | ((d: unknown) => boolean)
    | Record<string, SchemaValue>
    | undefined;

  if (Array.isArray(allowedOriginsOrOptions)) {
    // Legacy form: (allowedOrigins, onMessage)
    allowedOrigins = allowedOriginsOrOptions;
    onMessage = onMessageOptional as (data: unknown) => void;
    possibleValidator = undefined;
  } else if (
    typeof allowedOriginsOrOptions === "object" &&
    allowedOriginsOrOptions !== null
  ) {
    // Options object form
    const opts =
      allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    allowedOrigins = opts.allowedOrigins;
    onMessage = opts.onMessage;
    possibleValidator = opts.validate;
  } else {
    throw new InvalidParameterError(
      "Invalid arguments for createSecurePostMessageListener.",
    );
  }

  if (
    !Array.isArray(allowedOrigins) ||
    allowedOrigins.some((o) => typeof o !== "string" || o === "*")
  ) {
    throw new InvalidParameterError(
      "allowedOrigins must be an array of specific origin strings.",
    );
  }
  if (typeof onMessage !== "function") {
    throw new InvalidParameterError("onMessage must be a function.");
  }
  // Modern browsers have window and addEventListener

  const allowedOriginSet = new Set(allowedOrigins);
  const abortController = new AbortController();

  const handler = (event: MessageEvent) => {
    if (!allowedOriginSet.has(event.origin)) {
      secureDevLog(
        "warn",
        "postMessage",
        "Message dropped from non-allowlisted origin",
        { origin: event.origin },
      );
      return;
    }
    try {
      let data: unknown;
      if (typeof event.data === "string") {
        // Pre-parse size guard to prevent huge JSON payloads from DoS'ing the process
        if (event.data.length > POSTMESSAGE_MAX_PAYLOAD_BYTES) {
          secureDevLog(
            "warn",
            "postMessage",
            "Dropped oversized string payload",
            { origin: event.origin, size: event.data.length },
          );
          return;
        }
        try {
          data = JSON.parse(event.data);
        } catch {
          secureDevLog(
            "warn",
            "postMessage",
            "Failed to parse incoming message JSON",
            { origin: event.origin },
          );
          return;
        }
      } else {
        data = event.data;
      }

      // If consumer provided a schema or validator via options, run hardened validation
      if (possibleValidator) {
        try {
          const validationResult = _validatePayload(
            data,
            possibleValidator as
              | ((d: unknown) => boolean)
              | Record<string, SchemaValue>,
          );
          if (!validationResult.valid) {
            void getPayloadFingerprint(data)
              .then((fp) => {
                secureDevLog(
                  "warn",
                  "postMessage",
                  "Message dropped due to failed payload validation",
                  {
                    origin: event.origin,
                    reason: validationResult.reason,
                    fingerprint: fp,
                  },
                );
              })
              .catch(() => {
                secureDevLog(
                  "warn",
                  "postMessage",
                  "Message dropped due to failed payload validation",
                  {
                    origin: event.origin,
                    reason: validationResult.reason,
                  },
                );
              });
            return; // Discard the message safely.
          }
        } catch (valErr) {
          secureDevLog("error", "postMessage", "Validator execution error", {
            origin: event.origin,
            error: sanitizeErrorForLogs(valErr),
          });
          return;
        }
      }

      onMessage(data);
    } catch (err) {
      secureDevLog("error", "postMessage", "Listener handler error", {
        origin: event.origin,
        error: sanitizeErrorForLogs(err),
      });
    }
  };

  window.addEventListener("message", handler, {
    signal: abortController.signal,
  });

  return {
    destroy: () => {
      abortController.abort();
    },
  };
}

// --- Subresource Integrity (SRI) Generator ---

/**
 * Generates a Subresource Integrity (SRI) hash for a given input.
 * Implements Security Constitution Rule 2.3 requirement for SRI support.
 *
 * @param input The string content or buffer of the resource.
 * @param algorithm The hashing algorithm to use (sha256, sha384, or sha512).
 * @returns A promise that resolves with the full SRI string (e.g., "sha384-...")
 * @throws CryptoUnavailableError If SubtleCrypto.digest is unavailable
 */
export async function generateSRI(
  input: string | ArrayBuffer,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384",
): Promise<string> {
  const crypto = await ensureCrypto();
  const subtle = (crypto as unknown as { subtle?: unknown }).subtle as
    | SubtleCrypto
    | undefined;
  if (!subtle || !subtle.digest) {
    throw new CryptoUnavailableError(
      "SubtleCrypto.digest is required for SRI generation.",
    );
  }

  let subtleAlgo: "SHA-256" | "SHA-384" | "SHA-512";
  if (algorithm === "sha256") {
    subtleAlgo = "SHA-256";
  } else if (algorithm === "sha384") {
    subtleAlgo = "SHA-384";
  } else if (algorithm === "sha512") {
    subtleAlgo = "SHA-512";
  } else {
    throw new InvalidParameterError(`Unsupported SRI algorithm: ${algorithm}`);
  }

  // CORRECTION: Reuse the module-level TextEncoder instance.
  if (input === undefined || input === null) {
    throw new InvalidParameterError(
      "Input content is required for SRI generation",
    );
  }

  const isString = typeof input === "string";
  // If input is a string, create a Uint8Array we can wipe later. If it's an
  // ArrayBuffer, leave it as-is (caller-owned) and do not mutate it.
  const dataForDigest: ArrayBuffer | Uint8Array = isString
    ? ENCODER.encode(input as string)
    : (input as ArrayBuffer);
  let digest: ArrayBuffer | undefined;

  try {
    // subtle.digest accepts a BufferSource (ArrayBuffer or ArrayBufferView).
    // dataForDigest is either an ArrayBuffer or Uint8Array, so cast to BufferSource.
    digest = await subtle.digest(subtleAlgo, dataForDigest as BufferSource);
    const base64Digest = _arrayBufferToBase64(digest);
    return `${algorithm}-${base64Digest}`;
  } finally {
    // Securely wipe all cryptographic material in memory where we created it.
    if (digest) {
      try {
        secureWipe(new Uint8Array(digest));
      } catch {
        /* best-effort wipe */
      }
    }
    if (isString) {
      try {
        secureWipe(dataForDigest as Uint8Array);
      } catch {
        /* best-effort wipe */
      }
    }
  }
}
