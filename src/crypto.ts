// SPDX-License-Identifier: MIT
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
 * eslint-disable functional/no-let, functional/immutable-data, prefer-const, unicorn/no-null, functional/prefer-readonly-type
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
  _arrayBufferToBase64,
  secureCompare,
  secureCompareAsync,
  secureDevLog as secureDevelopmentLog,
} from "./utils";
import { SHARED_ENCODER } from "./encoding";

/* -------------------------------------------------------------------------- */
/* Helpers & environment detection                                             */
/* -------------------------------------------------------------------------- */

/**
 * Create a cross-runtime AbortError-compatible object.
 * Ensures `.name === "AbortError"` for easier detection in consuming code.
 */
function makeAbortError(message = "Operation aborted"): Error {
  try {
    if (typeof DOMException !== "undefined") {
      const ex = new DOMException(message, "AbortError");
      // Some runtimes may differ — ensure name is correct.
      (ex as any).name = "AbortError";
      return ex;
    }
  } catch {
    // Fall through to generic Error below.
  }
  const e = new Error(message);
  (e as any).name = "AbortError";
  return e;
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
function checkAbortOrHidden(signal?: AbortSignal, enforceVisibility = true): void {
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
  return Boolean(maybeCrypto && typeof maybeCrypto.getRandomValues === "function");
}

export async function hasRandomUUID(): Promise<boolean> {
  try {
    const crypto = await ensureCrypto();
    return typeof (crypto as Crypto & { readonly randomUUID?: () => string }).randomUUID === "function";
  } catch {
    return false;
  }
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
  validateNumericParameter(size, "size", 1, 1024);

  const isValidAlphabetInput = typeof alphabet === "string" && alphabet.length > 0 && alphabet.length <= 256;
  if (!isValidAlphabetInput) {
    throw new InvalidParameterError("Alphabet must be a string with 1 to 256 characters.");
  }

  const uniqueChars = new Set(alphabet);
  if (uniqueChars.size !== alphabet.length) {
    throw new InvalidParameterError("Alphabet must contain only unique characters.");
  }

  const length = alphabet.length;
  if (length === 1) return { len: length, mask: 0, step: size };

  const bits = Math.ceil(Math.log2(length));
  const mask = (1 << bits) - 1;
  const acceptanceRatio = length / (mask + 1);

  // Keep the heuristic explicit: if acceptance ratio < 1/30 we consider it inefficient
  const MIN_ACCEPTANCE_RATIO = 1 / 30;
  if (acceptanceRatio > 0 && acceptanceRatio < MIN_ACCEPTANCE_RATIO) {
    throw new InvalidParameterError(`Alphabet size ${length} is inefficient for sampling.`);
  }

  const rawStep = Math.ceil((1.6 * mask * size) / length);
  const step = Math.min(rawStep, 4096);
  if (rawStep > 4096) {
    throw new InvalidParameterError("Combination of alphabet/size requires too many random bytes.");
  }

  return { len: length, mask, step };
}

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

export const URL_ALPHABET =
  "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
const HEX_ALPHABET = "0123456789abcdef";

/* -------------------------------------------------------------------------- */
/* Low-level random bytes                                                      */
/* -------------------------------------------------------------------------- */

export function assertCryptoAvailableSync(): Crypto {
  const crypto = (globalThis as { readonly crypto?: Crypto }).crypto;
  if (!crypto || typeof crypto.getRandomValues !== "function") {
    const error = new CryptoUnavailableError(
      "Synchronous Web Crypto API is not available in this environment",
    );
    Object.defineProperty(error, "code", {
      value: "CRYPTO_UNAVAILABLE_SYNC",
      configurable: false,
      enumerable: false,
      writable: false,
    });
    throw error;
  }
  return crypto;
}

export function getSecureRandomBytesSync(length = 1): Uint8Array {
  validateNumericParameter(length, "length", 1, 4096);
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
export async function getSecureRandomAsync(options?: {
  readonly signal?: AbortSignal;
  readonly enforceVisibility?: boolean;
}): Promise<number> {
  const crypto = await ensureCrypto();
  checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);

  if (typeof BigUint64Array !== "undefined") {
    try {
      const buffer = new BigUint64Array(1);
      crypto.getRandomValues(buffer);
      const value = buffer[0];
      if (value === undefined) throw new CryptoUnavailableError("Failed to generate random value.");
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      // Reduce to 52 bits of precision (safe for Number)
      return Number(value >> BigInt(12)) / 2 ** 52;
    } catch (err) {
      // In development log this unexpected failure; production falls back silently.
      if (isDevelopment()) {
        secureDevelopmentLog("warn", "security-kit", "BigUint64 fallback: %o", err);
      }
      // fall through to 32-bit path
    }
  }

  const buffer = new Uint32Array(1);
  const cryptoWithGet = crypto;
  cryptoWithGet.getRandomValues(buffer);
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
  options?: { readonly signal?: AbortSignal; readonly enforceVisibility?: boolean },
): Promise<number> {
  const MAX_SAFE_RANGE = 2 ** 31;
  validateNumericParameter(min, "min", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  validateNumericParameter(max, "max", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  if (min > max) throw new InvalidParameterError("min must be less than or equal to max.");
  if (min === max) return min;

  const crypto = await ensureCrypto();
  const rangeBig = BigInt(max) - BigInt(min) + BigInt(1);
  const RANDOM_ITERATION_CAP = 5000;

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
        if (r !== undefined && r < threshold64) return min + Number(r % rangeBig);
        if (index % 128 === 127) await Promise.resolve();
      }
    } finally {
      secureWipe(array64, { forbidShared: true });
    }
    return undefined;
  };

  if (rangeBig <= BigInt(0x100000000)) {
    const v = await tryUint32();
    if (v !== undefined) return v;
  } else if (typeof BigUint64Array !== "undefined") {
    const v = await tryUint64();
    if (v !== undefined) return v;
  } else {
    throw new InvalidParameterError("Range too large for this platform.");
  }

  throw new RandomGenerationError("Failed to generate unbiased random integer within safety limits.");
}

/* -------------------------------------------------------------------------- */
/* Throttling helpers                                                          */
/* -------------------------------------------------------------------------- */

export async function shouldExecuteThrottledAsync(
  probability: number,
  options?: { readonly signal?: AbortSignal; readonly enforceVisibility?: boolean },
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
  options?: { readonly signal?: AbortSignal; readonly enforceVisibility?: boolean },
): Promise<string> {
  const { len, mask, step } = computeAlphabetParameters(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  const crypto = await ensureCrypto();
  const bytes = new Uint8Array(step);
  const MAX_ITER = 500;

  try {
    // Preallocate result array for lower allocation churn
    const outArr: string[] = new Array(size);
    let pos = 0;

    for (let iter = 0; iter < MAX_ITER && pos < size; iter++) {
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      crypto.getRandomValues(bytes);
      for (let index = 0; index < step && pos < size; index++) {
        const charIndex = (bytes[index] as number) & mask;
        if (charIndex < len) {
          outArr[pos++] = alphabet[charIndex] as string;
        }
      }
      if (pos === size) return outArr.join("");
      // Yield to event loop to keep UI responsive
      await Promise.resolve();
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
    }

    if (pos === size) return outArr.join("");
    // If we fall through, build partial string for diagnostics then throw
    const partial = outArr.slice(0, pos).join("");
    throw new RandomGenerationError("Failed to generate secure string within safety limits.");
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
  options?: { readonly signal?: AbortSignal; readonly enforceVisibility?: boolean },
): string {
  const { len, mask, step } = computeAlphabetParameters(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  const crypto = assertCryptoAvailableSync();
  const bytes = new Uint8Array(step);
  try {
    const outArr: string[] = new Array(size);
    let pos = 0;

    // Cap attempts to avoid long blocking behavior on pathological alphabets
    const MAX_ITER = 500;
    for (let iter = 0; iter < MAX_ITER && pos < size; iter++) {
      checkAbortOrHidden(options?.signal, options?.enforceVisibility ?? true);
      crypto.getRandomValues(bytes);
      for (let index = 0; index < step && pos < size; index++) {
        const charIndex = (bytes[index] as number) & mask;
        if (charIndex < len) {
          outArr[pos++] = alphabet[charIndex] as string;
        }
      }
      if (pos === size) return outArr.join("");
    }

    throw new RandomGenerationError("Failed to generate secure string within safety limits.");
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
 * Return a wipeable Uint8Array of hex-encoded ascii bytes (two hex chars per byte).
 * Caller must call `secureWipe` when finished.
 */
export function generateSecureIdBytesSync(byteLength = 32): Uint8Array {
  validateNumericParameter(byteLength, "byteLength", 1, 256);
  // Generate raw random bytes (wipeable) and return them
  const bytes = getSecureRandomBytesSync(byteLength);
  return bytes;
}

/**
 * Async wipeable bytes generator.
 */
export async function generateSecureBytesAsync(byteLength = 32, options?: { readonly signal?: AbortSignal; readonly enforceVisibility?: boolean }): Promise<Uint8Array> {
  validateNumericParameter(byteLength, "byteLength", 1, 256);
  // Use ensureCrypto to satisfy environments where crypto is async-only
  await ensureCrypto();
  // Use sync crypto path after ensureCrypto to get random bytes quickly:
  const bytes = getSecureRandomBytesSync(byteLength);
  return bytes;
}

/* -------------------------------------------------------------------------- */
/* UUID                                                                       */
/* -------------------------------------------------------------------------- */

export async function generateSecureUUID(): Promise<string> {
  const crypto = await ensureCrypto();
  const cryptoWithUUID = crypto as Crypto & { readonly randomUUID?: () => string };
  if (typeof cryptoWithUUID.randomUUID === "function") {
    return cryptoWithUUID.randomUUID();
  }
  const bytes = new Uint8Array(16);
  try {
    crypto.getRandomValues(bytes);
    if (bytes.length !== 16) throw new CryptoUnavailableError("Failed to generate sufficient bytes for UUID.");
    bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
    bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
}

/* -------------------------------------------------------------------------- */
/* Key & Nonce Generation                                                      */
/* -------------------------------------------------------------------------- */

type KeyUsageAlias = "encrypt" | "decrypt" | "wrapKey" | "unwrapKey";
type KeyUsagesArray = ReadonlyArray<KeyUsageAlias>;

const ALLOWED_KEY_USAGES = new Set<KeyUsageAlias>(["encrypt", "decrypt", "wrapKey", "unwrapKey"]);

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
  let bitLength: number;

  if (lengthBits !== undefined && deprecatedLength !== undefined) {
    throw new InvalidParameterError("Cannot specify both lengthBits and deprecated length.");
  }
  if (deprecatedLength !== undefined && isDevelopment()) {
    secureDevelopmentLog("warn", "security-kit", "DEPRECATION: `length` is deprecated. Use `lengthBits`.");
  }

  bitLength = lengthBits ?? deprecatedLength ?? 256;
  if (bitLength !== 128 && bitLength !== 256) {
    throw new InvalidParameterError("Key length must be 128 or 256 bits.");
  }

  if (!Array.isArray(usages) || usages.length === 0 || usages.some((u) => !ALLOWED_KEY_USAGES.has(u))) {
    throw new InvalidParameterError("Invalid key usages provided.");
  }

  const crypto = await ensureCrypto();
  const subtle = (crypto as { readonly subtle?: SubtleCrypto }).subtle;
  if (!subtle) throw new CryptoUnavailableError("SubtleCrypto is unavailable.");

  const extractable = false;
  if (typeof subtle.generateKey === "function") {
    return subtle.generateKey({ name: "AES-GCM", length: bitLength }, extractable, usages as readonly KeyUsage[]);
  }

  const keyData = new Uint8Array(bitLength / 8);
  try {
    crypto.getRandomValues(keyData);
    return await subtle.importKey("raw", keyData, { name: "AES-GCM", length: bitLength }, extractable, Array.from(usages) as KeyUsage[]);
  } finally {
    secureWipe(keyData, { forbidShared: true });
  }
}

export function createAesGcmNonce(byteLength = 12): Uint8Array {
  validateNumericParameter(byteLength, "byteLength", 12, 16);
  return getSecureRandomBytesSync(byteLength);
}

export function createAesGcmKey128(usages: KeyUsagesArray = ["encrypt", "decrypt"]): Promise<CryptoKey> {
  return createOneTimeCryptoKey({ lengthBits: 128, usages });
}

export function createAesGcmKey256(usages: KeyUsagesArray = ["encrypt", "decrypt"]): Promise<CryptoKey> {
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
    throw new CryptoUnavailableError("SubtleCrypto.digest is required for SRI generation.");
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
    throw new InvalidParameterError("Input content is required for SRI generation");
  }

  // IMPORTANT: If callers pass a string here, JavaScript strings are immutable
  // and cannot be reliably wiped from memory. We therefore create an internal
  // Uint8Array copy which we wipe after use. For sensitive secrets prefer
  // passing an ArrayBuffer/Uint8Array so callers can securely wipe the source.
  let internalView: Uint8Array | null = null;
  let digest: ArrayBuffer | undefined;

  try {
    if (typeof input === "string") {
      internalView = SHARED_ENCODER.encode(input);
    } else {
      const buf = input;
      internalView = new Uint8Array(buf.byteLength);
      internalView.set(new Uint8Array(buf));
    }

    digest = await subtle.digest(subtleAlgo, internalView as BufferSource);
    return `${algorithm}-${_arrayBufferToBase64(digest)}`;
  } finally {
    if (digest) secureWipe(new Uint8Array(digest), { forbidShared: true });
    if (internalView) secureWipe(internalView, { forbidShared: true });
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
});
