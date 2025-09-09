// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Core cryptographic primitives for generating secure random data,
 * IDs, UUIDs, keys, and nonces.
 *
 * Notes about linting & immutability:
 * - This file intentionally allows a *very small* number of local mutations
 *   for performance and for explicit, timely zeroing of sensitive memory via
 *   `secureWipe`. Those mutation sites are narrowly scoped and documented.
 *
 */

import {
  CryptoUnavailableError,
  InvalidParameterError,
  RandomGenerationError,
} from "./errors";
import { ensureCrypto } from "./state";
import { isDevelopment } from "./environment";
import {
  secureWipe,
  validateNumericParam as validateNumericParameter,
  validateProbability,
  secureCompare,
  secureCompareAsync,
  secureDevLog as secureDevelopmentLog,
  emitMetric,
} from "./utils";
import { arrayBufferToBase64 } from "./encoding-utils";
import { SHARED_ENCODER } from "./encoding";

// Lightweight AbortError subclass so we can return a typed, non-mutated Error
// instance without assigning properties at runtime (keeps immutable-data rules happy)
class AbortError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "AbortError";
    // Ensure instanceof works across different JS runtimes
    Object.setPrototypeOf(this, AbortError.prototype);
  }
}

/* -------------------------------------------------------------------------- */
/* Public option types                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Reusable options for APIs that support AbortSignal and optional visibility
 * enforcement. Exported so d.ts consumers get a clear type in generated
 * declaration files.
 */
export interface RandomOptions {
  readonly signal?: AbortSignal;
  readonly enforceVisibility?: boolean;
}

/* -------------------------------------------------------------------------- */
/* Helpers & environment detection                                             */
/* -------------------------------------------------------------------------- */

/**
 * Optional: export a Node-friendly type to avoid leaking DOM types to consumers.
 */
export type AbortSignalLike = Pick<AbortSignal, "aborted">;

/**
 * Create a cross-runtime AbortError-compatible object.
 * Ensures `.name === "AbortError"` for easier detection in consuming code.
 */
function makeAbortError(message = "Operation aborted"): Error {
  try {
    if (typeof DOMException !== "undefined") {
      // Create a DOMException with the AbortError type where available.
      const ex = new DOMException(message, "AbortError");
      // Do not attempt to mutate host-provided objects. If the runtime for
      // some reason does not expose the expected name, return a fresh Error
      // with the correct name instead of mutating the DOMException.
      if (ex.name !== "AbortError") {
        return new AbortError(message);
      }
      return ex as unknown as Error;
    }
  } catch {
    // Fall through to generic Error below.
  }
  return new AbortError(message);
}

/**
 * Centralized abort & visibility check.
 *
 * @param signal optional AbortSignal
 * @param enforceVisibility default true; set false for headless/background consumers
 *
 * NOTE: The `document.hidden` visibility enforcement is part of your project's
 * Constitution (§2.11). For non-browser/headless contexts callers can set
 * `enforceVisibility` to `false`.
 */
function checkAbortOrHidden(
  signal?: AbortSignal,
  enforceVisibility = true,
): void {
  if (signal?.aborted) throw makeAbortError();
  if (enforceVisibility && typeof document !== "undefined" && document.hidden) {
    throw new RandomGenerationError(
      "Aborted due to hidden document (see Constitution §2.11).",
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Runtime capability helpers                                                  */
/* -------------------------------------------------------------------------- */

export function hasSyncCrypto(): boolean {
  const maybeCrypto = (globalThis as { readonly crypto?: Crypto }).crypto;
  return Boolean(
    maybeCrypto && typeof maybeCrypto.getRandomValues === "function",
  );
}

export async function hasRandomUUID(): Promise<boolean> {
  try {
    const crypto = await ensureCrypto();
    return (
      typeof (crypto as Crypto & { readonly randomUUID?: () => string })
        .randomUUID === "function"
    );
  } catch {
    return false;
  }
}

/**
 * Synchronous helper for immediate feature detection (review finding #13)
 */
export function hasRandomUUIDSync(): boolean {
  const maybe = (globalThis as { readonly crypto?: Crypto }).crypto as
    | (Crypto & { readonly randomUUID?: () => string })
    | undefined;
  return Boolean(maybe?.randomUUID && typeof maybe.randomUUID === "function");
}

/**
 * Export a capability matrix for consumers and diagnostics (review finding #2).
 */
export function getCryptoCapabilities(): Readonly<{
  readonly hasSyncCrypto: boolean;
  readonly hasSubtle: boolean;
  readonly hasDigest: boolean;
  readonly hasRandomUUIDSync: boolean;
  readonly hasRandomUUIDAsyncLikely: boolean; // true if subtle/crypto likely available
  readonly hasBigUint64: boolean;
}> {
  const c = (
    globalThis as {
      readonly crypto?: Crypto & {
        readonly randomUUID?: () => string;
        readonly subtle?: SubtleCrypto;
      };
    }
  ).crypto;

  return Object.freeze({
    hasSyncCrypto: Boolean(c && typeof c.getRandomValues === "function"),
    hasSubtle: Boolean(c?.subtle),
    hasDigest: Boolean(c?.subtle && typeof c.subtle.digest === "function"),
    hasRandomUUIDSync: Boolean(
      c?.randomUUID && typeof c.randomUUID === "function",
    ),
    hasRandomUUIDAsyncLikely: Boolean(c),
    hasBigUint64: typeof BigUint64Array !== "undefined",
  });
}

/* -------------------------------------------------------------------------- */
/* Alphabet parameter computation (audit-friendly)                             */
/* -------------------------------------------------------------------------- */

function computeAlphabetParameters(
  alphabet: string,
  size: number,
): {
  readonly len: number;
  readonly mask: number;
  readonly step: number;
} {
  validateNumericParameter(size, "size", 1, MAX_SECURE_STRING_SIZE);

  const isValidAlphabetInput =
    typeof alphabet === "string" &&
    alphabet.length > 0 &&
    alphabet.length <= 256;
  if (!isValidAlphabetInput) {
    throw new InvalidParameterError(
      "Alphabet must be a string with 1 to 256 characters.",
    );
  }

  const uniqueChars = new Set(alphabet);
  if (uniqueChars.size !== alphabet.length) {
    throw new InvalidParameterError(
      "Alphabet must contain only unique characters.",
    );
  }

  const length = alphabet.length;
  if (length === 1) return { len: length, mask: 0, step: size };

  const bits = Math.ceil(Math.log2(length));
  const mask = (1 << bits) - 1;
  const acceptanceRatio = length / (mask + 1);

  // Keep the heuristic explicit: if acceptance ratio < 1/30 we consider it inefficient
  if (acceptanceRatio > 0 && acceptanceRatio < MIN_ACCEPTANCE_RATIO) {
    throw new InvalidParameterError(
      `Alphabet size ${length} is inefficient for sampling (ratio ${acceptanceRatio.toFixed(4)}).`,
    );
  }

  const rawStep = Math.ceil((REJECTION_STEP_FACTOR * mask * size) / length);
  const step = Math.min(rawStep, MAX_RANDOM_BYTES_SYNC);
  if (rawStep > MAX_RANDOM_BYTES_SYNC) {
    throw new InvalidParameterError(
      "Combination of alphabet/size requires too many random bytes.",
    );
  }

  return { len: length, mask, step };
}

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

// Publicly documented limits for discoverability and consistent error messages.
export const MAX_RANDOM_BYTES_SYNC = 4096 as const;
export const MAX_ID_STRING_LENGTH = 256 as const;
export const MAX_ID_BYTES_LENGTH = 256 as const;
export const MAX_SECURE_STRING_SIZE = 1024 as const; // conservative upper bound
export const RANDOM_INT_ITERATION_CAP = 5000 as const; // unbiased int generation cap
export const REJECTION_STEP_FACTOR = 1.6 as const; // heuristic factor for step sizing
export const MIN_ACCEPTANCE_RATIO = 1 / 30; // audit-able threshold

export const URL_ALPHABET =
  "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
const HEX_ALPHABET = "0123456789abcdef";

// Precompute a fast hex lookup table for byte -> two-char hex conversion.
const _HEX_LOOKUP: readonly string[] = Object.freeze(
  Array.from({ length: 256 }, (_, index) =>
    index.toString(16).padStart(2, "0"),
  ),
);

function bytesToHex(bytes: Uint8Array): string {
  // Functional mapping avoids in-place mutation and satisfies immutable-data
  // lint rules while remaining allocation-efficient for small arrays.
  return Array.from(bytes, (b) => _HEX_LOOKUP[b]!).join("");
}

/* -------------------------------------------------------------------------- */
/* Low-level random bytes                                                      */
/* -------------------------------------------------------------------------- */

export function assertCryptoAvailableSync(): Crypto {
  const crypto = (globalThis as { readonly crypto?: Crypto }).crypto;
  if (!crypto || typeof crypto.getRandomValues !== "function") {
    const error = new CryptoUnavailableError(
      "Synchronous Web Crypto API is not available in this environment",
    );
    // CryptoUnavailableError already defines a stable `code` property.
    // Avoid mutating the instance further to satisfy immutable-data lint rules.
    throw error;
  }
  return crypto;
}

export function getSecureRandomBytesSync(length = 1): Uint8Array {
  validateNumericParameter(length, "length", 1, MAX_RANDOM_BYTES_SYNC);
  const crypto = assertCryptoAvailableSync();
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Async random number in [0, 1).
 * Options:
 *  - signal?: AbortSignal
 *  - enforceVisibility?: boolean (default true)
 */
export async function getSecureRandomAsync(
  options?: RandomOptions,
): Promise<number> {
  const crypto = await ensureCrypto();
  checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);

  if (typeof BigUint64Array !== "undefined") {
    try {
      const buffer = new BigUint64Array(1);
      crypto.getRandomValues(buffer);
      const value = buffer[0];
      if (value === undefined)
        throw new CryptoUnavailableError("Failed to generate random value.");
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      // Reduce to 52 bits of precision (safe for Number)
      return Number(value >> BigInt(12)) / 2 ** 52;
    } catch (error) {
      // In development log this unexpected failure; production falls back silently.
      if (isDevelopment()) {
        secureDevelopmentLog(
          "warn",
          "security-kit",
          "BigUint64 fallback: %o",
          error,
        );
      }
      // fall through to 32-bit path
    }
  }

  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export function getSecureRandom(): number {
  const crypto = assertCryptoAvailableSync();
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

/* -------------------------------------------------------------------------- */
/* Secure integer generation within range                                      */
/* -------------------------------------------------------------------------- */

export async function getSecureRandomInt(
  min: number,
  max: number,
  options?: RandomOptions,
): Promise<number> {
  const MAX_SAFE_RANGE = 2 ** 31;
  validateNumericParameter(min, "min", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  validateNumericParameter(max, "max", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  if (min > max)
    throw new InvalidParameterError("min must be less than or equal to max.");
  // Fast-path: zero-width range returns the boundary value deterministically.
  if (min === max) return min;

  const crypto = await ensureCrypto();
  const rangeBig = BigInt(max) - BigInt(min) + BigInt(1);
  const RANDOM_ITERATION_CAP = RANDOM_INT_ITERATION_CAP;

  /* eslint-disable functional/no-let -- Controlled local
    loop counters are necessary here for performance in the rejection-sampling
    loop. */
  const tryUint32 = async (): Promise<number | undefined> => {
    const range = Number(rangeBig);
    const array = new Uint32Array(1);
    const threshold = Math.floor(0x100000000 / range) * range;
    try {
      for (let index = 0; index < RANDOM_ITERATION_CAP; index++) {
        if (options?.signal?.aborted) throw makeAbortError();
        checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
        crypto.getRandomValues(array);
        const r = (array[0] ?? 0) >>> 0;
        if (r < threshold) return min + (r % range);
        if (index % 128 === 127) await Promise.resolve();
      }
    } finally {
      secureWipe(array, { forbidShared: true });
    }
    return undefined;
  };
  /* eslint-enable functional/no-let */

  /* eslint-disable functional/no-let -- Controlled local
    loop counters are necessary here for performance in the rejection-sampling
    loop. */
  const tryUint64 = async (): Promise<number | undefined> => {
    if (typeof BigUint64Array === "undefined") return undefined;
    const array64 = new BigUint64Array(1);
    const space = BigInt(1) << BigInt(64);
    const threshold64 = space - (space % rangeBig);
    try {
      for (let index = 0; index < RANDOM_ITERATION_CAP; index++) {
        if (options?.signal?.aborted) throw makeAbortError();
        checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
        crypto.getRandomValues(array64);
        const r = array64[0];
        if (r !== undefined && r < threshold64)
          return min + Number(r % rangeBig);
        if (index % 128 === 127) await Promise.resolve();
      }
    } finally {
      secureWipe(array64, { forbidShared: true });
    }
    return undefined;
  };
  /* eslint-enable functional/no-let */

  // Track which path exhausted its iteration cap to aid diagnostics
  // eslint-disable-next-line functional/no-let -- small local state for telemetry
  let capPath: "u32" | "u64" | undefined;
  if (rangeBig <= BigInt(0x100000000)) {
    const v = await tryUint32();
    if (v !== undefined) return v;
    capPath = "u32";
  } else if (typeof BigUint64Array !== "undefined") {
    const v = await tryUint64();
    if (v !== undefined) return v;
    capPath = "u64";
  } else {
    throw new InvalidParameterError("Range too large for this platform.");
  }

  try {
    // Emit a small, sanitized signal for iteration-cap exhaustion.
    emitMetric("rng.int.cap_exhausted", 1, { reason: "cap" });
    if (isDevelopment()) {
      secureDevelopmentLog(
        "warn",
        "security-kit",
        "getSecureRandomInt iteration cap exhausted (path=%s)",
        capPath ?? "unknown",
      );
    }
  } catch {
    /* telemetry/logging best-effort */
  }

  throw new RandomGenerationError(
    "Failed to generate unbiased random integer within safety limits.",
  );
}

/* -------------------------------------------------------------------------- */
/* Throttling helpers                                                          */
/* -------------------------------------------------------------------------- */

export async function shouldExecuteThrottledAsync(
  probability: number,
  options?: RandomOptions,
): Promise<boolean> {
  validateProbability(probability);
  return (await getSecureRandomAsync(options)) < probability;
}

export function shouldExecuteThrottled(probability: number): boolean {
  validateProbability(probability);
  return getSecureRandom() < probability;
}

/* -------------------------------------------------------------------------- */
/* Secure string & ID generation                                               */
/* -------------------------------------------------------------------------- */

/**
 * Internal async string sampler. Returns a string of targetSize using the
 * provided alphabet. Uses preallocated arrays + join to minimize ephemeral
 * allocations and allow wiping the random bytes buffer.
 *
 * This function intentionally uses a few local mutations for performance.
 */
async function generateSecureStringInternalAsync(
  alphabet: string,
  size: number,
  options?: RandomOptions,
): Promise<string> {
  const { len, mask, step } = computeAlphabetParameters(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  const crypto = await ensureCrypto();
  const bytes = new Uint8Array(step);
  const MAX_ITER = 500;

  try {
    /* eslint-disable functional/no-let, functional/immutable-data, functional/prefer-readonly-type --
       Justified: tight loop uses a small number of controlled local mutations for
       performance and immediate wiping of random bytes. Scope limited to this
       function. */
    // Preallocate result array for lower allocation churn
    const outArray: string[] = new Array<string>(size);
    let pos = 0;

    for (let iter = 0; iter < MAX_ITER && pos < size; iter++) {
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      crypto.getRandomValues(bytes);
      for (let index = 0; index < step && pos < size; index++) {
        const charIndex = (bytes[index] as number) & mask;
        if (charIndex < len) {
          outArray[pos++] = alphabet[charIndex] as string;
        }
      }
      if (pos === size) {
        /* eslint-enable functional/no-let, functional/immutable-data, functional/prefer-readonly-type */
        return outArray.join("");
      }
      // Yield to event loop to keep UI responsive
      await Promise.resolve();
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
    }

    if (pos === size) {
      return outArray.join("");
    }

    // If we fall through, build partial string for diagnostics then throw
    throw new RandomGenerationError(
      "Failed to generate secure string within safety limits.",
    );
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
}

/**
 * Sync variant of string generation. Uses the sync crypto path and mirrors the
 * async algorithm but without yielding.
 *
 * NOTE: this will throw CryptoUnavailableError if sync crypto is not present.
 */
export function generateSecureStringSync(
  alphabet: string,
  size: number,
  options?: RandomOptions,
): string {
  const { len, mask, step } = computeAlphabetParameters(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  const crypto = assertCryptoAvailableSync();
  const bytes = new Uint8Array(step);
  try {
    /* eslint-disable functional/no-let, functional/immutable-data, functional/prefer-readonly-type --
       Justified: tight loop uses a small number of controlled local mutations for
       performance and immediate wiping of random bytes. Scope limited to this
       function. */
    const outArray: string[] = new Array<string>(size);
    let pos = 0;

    // Cap attempts to avoid long blocking behavior on pathological alphabets
    const MAX_ITER = 500;
    for (let iter = 0; iter < MAX_ITER && pos < size; iter++) {
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      crypto.getRandomValues(bytes);
      for (let index = 0; index < step && pos < size; index++) {
        const charIndex = (bytes[index] as number) & mask;
        if (charIndex < len) {
          outArray[pos++] = alphabet[charIndex] as string;
        }
      }
      if (pos === size) {
        /* eslint-enable functional/no-let, functional/immutable-data, functional/prefer-readonly-type */
        return outArray.join("");
      }
    }

    throw new RandomGenerationError(
      "Failed to generate secure string within safety limits.",
    );
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
}

/* Public API: string-returning IDs (convenient but non-wipeable) */

/**
 * Async generator for hex ID strings (uses async-safe path).
 */
export async function generateSecureId(length = 64): Promise<string> {
  validateNumericParameter(length, "length", 1, 256);
  // Prefer async path for portability across runtimes (workers, node, etc.)
  return generateSecureStringInternalAsync(HEX_ALPHABET, length);
}

// Backwards-compatible async API used by tests and consumers: wrapper around the
// internal async generator. Kept as a named export for compatibility.
export async function generateSecureStringAsync(
  alphabet: string,
  size: number,
  options?: RandomOptions,
): Promise<string> {
  return generateSecureStringInternalAsync(alphabet, size, options);
}

/**
 * Sync generator for hex ID strings. Will throw if sync crypto is unavailable.
 */
export function generateSecureIdSync(length = 64): string {
  validateNumericParameter(length, "length", 1, 256);
  return generateSecureStringSync(HEX_ALPHABET, length);
}

/* -------------------------------------------------------------------------- */
/* Buffer-returning APIs (wipeable)                                            */
/* -------------------------------------------------------------------------- */

/**
 * Return a wipeable Uint8Array of raw random bytes.
 * Caller must call `secureWipe` when finished.
 */
export function generateSecureIdBytesSync(byteLength = 32): Uint8Array {
  validateNumericParameter(byteLength, "byteLength", 1, 256);
  // Generate raw random bytes (wipeable) and return them
  const bytes = getSecureRandomBytesSync(byteLength);
  return bytes;
}

/**
 * Async wipeable bytes generator. Returns a wipeable Uint8Array of raw random bytes.
 * Caller must call `secureWipe` when finished.
 */
export async function generateSecureBytesAsync(
  byteLength = 32,
  _options?: RandomOptions,
): Promise<Uint8Array> {
  validateNumericParameter(byteLength, "byteLength", 1, 256);
  // Use ensureCrypto to satisfy environments where crypto is async-only
  const crypto = await ensureCrypto();
  // Use the returned crypto instance directly to avoid assumptions about
  // globalThis.crypto wiring in different runtimes.
  const out = new Uint8Array(byteLength);
  crypto.getRandomValues(out);
  return out;
}

/* -------------------------------------------------------------------------- */
/* UUID                                                                       */
/* -------------------------------------------------------------------------- */

export async function generateSecureUUID(): Promise<string> {
  /* eslint-disable functional/immutable-data -- We must mutate the 16-byte
     UUID buffer to set version/variant bits and then securely wipe it. */
  const crypto = await ensureCrypto();
  const cryptoWithUUID = crypto as Crypto & {
    readonly randomUUID?: () => string;
  };
  if (typeof cryptoWithUUID.randomUUID === "function") {
    return cryptoWithUUID.randomUUID();
  }
  const bytes = new Uint8Array(16);
  try {
    crypto.getRandomValues(bytes);
    if (bytes.length !== 16)
      throw new CryptoUnavailableError(
        "Failed to generate sufficient bytes for UUID.",
      );
    bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
    bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
    const hex = bytesToHex(bytes);
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32),
    ].join("-");
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
  /* eslint-enable functional/immutable-data */
}

/* -------------------------------------------------------------------------- */
/* Key & Nonce Generation                                                      */
/* -------------------------------------------------------------------------- */

type KeyUsageAlias = "encrypt" | "decrypt" | "wrapKey" | "unwrapKey";
type KeyUsagesArray = ReadonlyArray<KeyUsageAlias>;

const ALLOWED_KEY_USAGES = new Set<KeyUsageAlias>([
  "encrypt",
  "decrypt",
  "wrapKey",
  "unwrapKey",
]);

export async function createOneTimeCryptoKey(
  options: {
    readonly lengthBits?: 128 | 256;
    /** @deprecated Use `lengthBits`. */
    readonly length?: 128 | 256;
    readonly usages?: KeyUsagesArray;
  } = {},
): Promise<CryptoKey> {
  const { lengthBits, usages = ["encrypt", "decrypt"] } = options;
  const deprecatedLength = (options as { readonly length?: 128 | 256 }).length;

  if (lengthBits !== undefined && deprecatedLength !== undefined) {
    throw new InvalidParameterError(
      "Cannot specify both lengthBits and deprecated length.",
    );
  }
  if (deprecatedLength !== undefined && isDevelopment()) {
    secureDevelopmentLog(
      "warn",
      "security-kit",
      "DEPRECATION: `length` is deprecated. Use `lengthBits`.",
    );
  }

  const bitLength = lengthBits ?? deprecatedLength ?? 256;
  if (bitLength !== 128 && bitLength !== 256) {
    throw new InvalidParameterError("Key length must be 128 or 256 bits.");
  }

  if (
    !Array.isArray(usages) ||
    usages.length === 0 ||
    usages.some((u) => !ALLOWED_KEY_USAGES.has(u))
  ) {
    throw new InvalidParameterError("Invalid key usages provided.");
  }

  const crypto = await ensureCrypto();
  const subtle = (crypto as { readonly subtle?: SubtleCrypto }).subtle;
  if (!subtle) throw new CryptoUnavailableError("SubtleCrypto is unavailable.");

  const extractable = false;
  // SECURITY: Prefer non-extractable key generation to avoid materializing raw key bytes.
  if (typeof subtle.generateKey === "function") {
    /* eslint-disable functional/prefer-readonly-type -- WebCrypto expects a mutable KeyUsage[]; usages is a readonly input so we create a fresh array. */
    const usagesArray = Array.from(usages) as KeyUsage[];
    /* eslint-enable functional/prefer-readonly-type */
    return subtle.generateKey(
      { name: "AES-GCM", length: bitLength },
      extractable,
      usagesArray,
    );
  }

  // Fallback: import raw key material only if generateKey is unavailable.
  if (typeof subtle.importKey === "function") {
    const keyData = new Uint8Array(bitLength / 8);
    try {
      crypto.getRandomValues(keyData);
      /* eslint-disable functional/prefer-readonly-type -- WebCrypto expects a mutable KeyUsage[]; usages is a readonly input so we create a fresh array. */
      const usagesArray = Array.from(usages) as KeyUsage[];
      /* eslint-enable functional/prefer-readonly-type */
      return await subtle.importKey(
        "raw",
        keyData,
        { name: "AES-GCM", length: bitLength },
        extractable,
        usagesArray,
      );
    } finally {
      // Ensure key material is wiped regardless of success/failure.
      secureWipe(keyData, { forbidShared: true });
    }
  }

  throw new CryptoUnavailableError(
    "SubtleCrypto.generateKey/importKey unavailable.",
  );
}

export function createAesGcmNonce(byteLength = 12): Uint8Array {
  validateNumericParameter(byteLength, "byteLength", 12, 16);
  return getSecureRandomBytesSync(byteLength);
}

export function createAesGcmKey128(
  usages: KeyUsagesArray = ["encrypt", "decrypt"],
): Promise<CryptoKey> {
  return createOneTimeCryptoKey({ lengthBits: 128, usages });
}

export function createAesGcmKey256(
  usages: KeyUsagesArray = ["encrypt", "decrypt"],
): Promise<CryptoKey> {
  return createOneTimeCryptoKey({ lengthBits: 256, usages });
}

/* -------------------------------------------------------------------------- */
/* Subresource Integrity (SRI)                                                 */
/* -------------------------------------------------------------------------- */

export async function generateSRI(
  input: string | ArrayBuffer,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384",
): Promise<string> {
  const crypto = await ensureCrypto();
  const subtle = (crypto as { readonly subtle?: SubtleCrypto }).subtle;
  if (!subtle?.digest) {
    throw new CryptoUnavailableError(
      "SubtleCrypto.digest is required for SRI generation.",
    );
  }

  const subtleAlgoMap = {
    sha256: "SHA-256",
    sha384: "SHA-384",
    sha512: "SHA-512",
  } as const;
  const subtleAlgo = subtleAlgoMap[algorithm];
  if (!subtleAlgo) {
    throw new InvalidParameterError(`Unsupported SRI algorithm: ${algorithm}`);
  }
  if (input == undefined) {
    throw new InvalidParameterError(
      "Input content is required for SRI generation",
    );
  }

  // IMPORTANT: If callers pass a string here, JavaScript strings are immutable
  // and cannot be reliably wiped from memory. We therefore create an internal
  // Uint8Array copy which we wipe after use. For sensitive secrets prefer
  // passing an ArrayBuffer/Uint8Array so callers can securely wipe the source.
  // internalView and digest are assigned then wiped in finally; local mutation is intentional.
  // eslint-disable-next-line functional/no-let -- controlled mutable locals for wiping
  let internalView: Uint8Array | undefined = undefined;
  // eslint-disable-next-line functional/no-let -- controlled mutable locals for wiping
  let digest: ArrayBuffer | undefined;

  try {
    if (typeof input === "string") {
      // Developer education signal: strings are not wipeable.
      if (isDevelopment()) {
        secureDevelopmentLog(
          "warn",
          "security-kit",
          "generateSRI received a string input. Strings are immutable and cannot be wiped. Prefer Uint8Array/ArrayBuffer for sensitive material.",
        );
      }
      internalView = SHARED_ENCODER.encode(input);
    } else {
      const buf = input;
      internalView = new Uint8Array(buf.byteLength);
      internalView.set(new Uint8Array(buf));
    }

    digest = await subtle.digest(subtleAlgo, internalView as BufferSource);
    return `${algorithm}-${arrayBufferToBase64(digest)}`;
  } finally {
    if (digest) {
      secureWipe(new Uint8Array(digest), { forbidShared: true });
    }
    if (internalView !== undefined) {
      secureWipe(internalView, { forbidShared: true });
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Public convenience surface                                                   */
/* -------------------------------------------------------------------------- */

export const SIMPLE_API = Object.freeze({
  getSecureRandomBytesSync,
  getSecureRandomAsync,
  getSecureRandom,
  generateSecureId,
  generateSecureIdSync,
  generateSecureUUID,
  generateSecureIdBytesSync,
  generateSecureBytesAsync,
  createAesGcmKey128,
  createAesGcmKey256,
  createAesGcmNonce,
  generateSRI,
  secureCompare,
  secureCompareAsync,
  hasSyncCrypto,
  hasRandomUUID,
  hasRandomUUIDSync,
  getCryptoCapabilities,
});

/* -------------------------------------------------------------------------- */
/* Vitest test stubs (place in tests/random.test.ts)                           */
/* -------------------------------------------------------------------------- */

/*
  Copy the following block into `tests/random.test.ts` in your project
  (Vitest + tsconfig configured for testing). These tests are intentionally
  small smoke tests to validate the most important behaviors.

import { describe, it, expect } from 'vitest';
import {
  generateSecureId,
  generateSecureIdSync,
  generateSecureIdBytesSync,
  generateSecureBytesAsync,
  generateSecureUUID,
  getSecureRandomInt,
  shouldExecuteThrottled,
} from '../src/secure-random-updated';

describe('Secure random smoke tests', () => {
  it('generates hex ids async & sync', async () => {
    const a = await generateSecureId(32);
    const b = generateSecureIdSync(32);
    expect(typeof a).toBe('string');
    expect(typeof b).toBe('string');
    expect(a).toHaveLength(32);
    expect(b).toHaveLength(32);
  });

  it('returns wipeable bytes', async () => {
    const bytes = generateSecureIdBytesSync(16);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(16);

    const bytesAsync = await generateSecureBytesAsync(16);
    expect(bytesAsync).toBeInstanceOf(Uint8Array);
    expect(bytesAsync.length).toBe(16);
  });

  it('generates UUID and matches pattern', async () => {
    const uuid = await generateSecureUUID();
    expect(typeof uuid).toBe('string');
    expect(uuid).toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i);
  });

  it('produces ints in range', async () => {
    for (let i = 0; i < 10; i++) {
      const v = await getSecureRandomInt(-1000, 1000);
      expect(v).toBeGreaterThanOrEqual(-1000);
      expect(v).toBeLessThanOrEqual(1000);
    }
  });

  it('throttling respects probability bounds', () => {
    expect(shouldExecuteThrottled(0)).toBe(false);
    expect(shouldExecuteThrottled(1)).toBe(true);
  });
});

*/
