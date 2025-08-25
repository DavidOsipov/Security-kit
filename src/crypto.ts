// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Core cryptographic primitives for generating secure random data,
 * IDs, UUIDs, keys, and nonces.
 * @module
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
  validateNumericParam,
  validateProbability,
  _arrayBufferToBase64,
  secureCompare,
  secureCompareAsync,
  secureDevLog,
} from "./utils";
import { SHARED_ENCODER } from "./encoding";

// --- Sync Crypto Guard ---
/**
 * Asserts that synchronous crypto primitives are available.
 * Throws a typed CryptoUnavailableError with stable code if not available.
 * @throws {CryptoUnavailableError} When sync crypto is unavailable
 */
export function assertCryptoAvailableSync(): Crypto {
  const crypto = (globalThis as { crypto?: Crypto }).crypto;
  if (!crypto || typeof crypto.getRandomValues !== "function") {
    const error = new CryptoUnavailableError(
      "Synchronous Web Crypto API is not available in this environment",
    );
    (error as { code?: string }).code = "CRYPTO_UNAVAILABLE_SYNC";
    throw error;
  }
  return crypto;
}
// Internal helpers to reduce complexity and keep logic auditable
function computeAlphabetParams(
  alphabet: string,
  size: number,
): {
  len: number;
  mask: number;
  step: number;
} {
  validateNumericParam(size, "size", 1, 1024);
  const isValidAlphabetInput =
    typeof alphabet === "string" &&
    alphabet.length > 0 &&
    alphabet.length <= 256;
  if (!isValidAlphabetInput) {
    throw new InvalidParameterError(
      "Alphabet must be a string with 1 to 256 characters.",
    );
  }
  const hasUniqueChars = (s: string) => new Set(s).size === s.length;
  if (!hasUniqueChars(alphabet)) {
    throw new InvalidParameterError(
      "Alphabet must contain only unique characters.",
    );
  }
  const len = alphabet.length;
  if (len === 1) return { len, mask: 0, step: size };

  const bits = Math.ceil(Math.log2(len));
  const mask = (1 << bits) - 1;
  const acceptanceRatio = len / (mask + 1);
  if (acceptanceRatio > 0 && 1 / acceptanceRatio > 30) {
    throw new InvalidParameterError(
      `Alphabet size ${len} is inefficient for sampling.`,
    );
  }

  const rawStep = Math.ceil((1.6 * mask * size) / len);
  const step = Math.min(rawStep, 4096);
  if (rawStep > 4096) {
    throw new InvalidParameterError(
      "Combination of alphabet/size requires too many random bytes.",
    );
  }
  return { len, mask, step };
}

function checkAbortOrHidden(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw typeof DOMException !== "undefined"
      ? new DOMException("Operation aborted", "AbortError")
      : new Error("Operation aborted");
  }
  if (typeof document !== "undefined" && document.hidden) {
    throw new RandomGenerationError(
      "Aborted due to hidden document (see Constitution §2.11).",
    );
  }
}

// --- Constants ---
export const URL_ALPHABET =
  "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
const HEX_ALPHABET = "0123456789abcdef";

// --- Random Data Generation ---
export function getSecureRandomBytesSync(length = 1): Uint8Array {
  validateNumericParam(length, "length", 1, 4096);
  const crypto = assertCryptoAvailableSync();
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

// Backwards-compatible async random with optional abort/visibility checks.
export async function getSecureRandomAsync(options?: {
  signal?: AbortSignal;
}): Promise<number> {
  const crypto = await ensureCrypto();
  // Check abort/visibility early to comply with Constitution §2.11
  checkAbortOrHidden(options?.signal);
  if (typeof BigUint64Array !== "undefined") {
    try {
      const buffer = new BigUint64Array(1);
      crypto.getRandomValues(buffer);
      const value = buffer[0];
      if (value === undefined)
        throw new CryptoUnavailableError("Failed to generate random value.");
      // Final visibility/abort check before returning
      checkAbortOrHidden(options?.signal);
      return Number(value >> BigInt(12)) / 2 ** 52;
    } catch {
      /* Fall through */
    }
  }
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  checkAbortOrHidden(options?.signal);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export function getSecureRandom(): number {
  const crypto = assertCryptoAvailableSync();
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export async function getSecureRandomInt(
  min: number,
  max: number,
  options?: { signal?: AbortSignal },
): Promise<number> {
  const MAX_SAFE_RANGE = 2 ** 31;
  validateNumericParam(min, "min", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  validateNumericParam(max, "max", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  if (min > max)
    throw new InvalidParameterError("min must be less than or equal to max.");
  if (min === max) return min;

  const crypto = await ensureCrypto();
  const rangeBig = BigInt(max) - BigInt(min) + BigInt(1);

  // Keep iteration caps bounded to avoid long blocking loops
  const RANDOM_ITERATION_CAP = 5000;
  const tryUint32 = async () => {
    const range = Number(rangeBig);
    const arr = new Uint32Array(1);
    const threshold = Math.floor(0x100000000 / range) * range;
    try {
      for (let i = 0; i < RANDOM_ITERATION_CAP; i++) {
        // Abort & visibility checks to preserve data integrity (§2.11)
        if (options?.signal?.aborted) {
          // Prefer DOMException when available for interoperable AbortError
          throw typeof DOMException !== "undefined"
            ? new DOMException("Operation aborted", "AbortError")
            : new Error("Operation aborted");
        }
        if (typeof document !== "undefined" && document.hidden) {
          throw new RandomGenerationError(
            "Aborted due to hidden document (see Constitution §2.11).",
          );
        }
        // Generous iteration limit to avoid undue failures; still bounded
        crypto.getRandomValues(arr);
        const r = (arr[0] ?? 0) >>> 0;
        if (r < threshold) return min + (r % range);
        // Yield periodically to avoid monopolizing the event loop in edge cases
        if (i % 128 === 127) await Promise.resolve();
      }
    } finally {
      secureWipe(arr, { forbidShared: true });
    }
    return undefined;
  };
  const tryUint64 = async () => {
    const arr64 = new BigUint64Array(1);
    const space = BigInt(1) << BigInt(64);
    const threshold64 = space - (space % rangeBig);
    try {
      for (let i = 0; i < RANDOM_ITERATION_CAP; i++) {
        if (options?.signal?.aborted) {
          throw typeof DOMException !== "undefined"
            ? new DOMException("Operation aborted", "AbortError")
            : new Error("Operation aborted");
        }
        if (typeof document !== "undefined" && document.hidden) {
          throw new RandomGenerationError(
            "Aborted due to hidden document (see Constitution §2.11).",
          );
        }
        crypto.getRandomValues(arr64);
        const r = arr64[0];
        if (r !== undefined && r < threshold64)
          return min + Number(r % rangeBig);
        if (i % 128 === 127) await Promise.resolve();
      }
    } finally {
      secureWipe(arr64, { forbidShared: true });
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
  throw new RandomGenerationError(
    "Failed to generate unbiased random integer within safety limits.",
  );
}

// --- Throttling ---
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

// --- Secure String & ID Generation ---
/**
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
  options?: { signal?: AbortSignal },
): string {
  const { len, mask, step } = computeAlphabetParams(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  let id = "";
  const crypto = assertCryptoAvailableSync();
  const bytes = new Uint8Array(step);
  const sampleId = (
    targetSize: number,
    alpha: string,
    alphaLen: number,
    bitMask: number,
    byteStep: number,
  ): string => {
    let out = "";
    // Cap attempts to avoid long blocking behavior on pathological alphabets
    for (let iter = 0; iter < 500 && out.length < targetSize; iter++) {
      // Abort & visibility checks to preserve data integrity (§2.11)
      checkAbortOrHidden(options?.signal);
      crypto.getRandomValues(bytes);
      for (let i = 0; i < byteStep && out.length < targetSize; i++) {
        const charIndex = (bytes[i] as number) & bitMask;
        if (charIndex < alphaLen) out += alpha[charIndex] as string;
      }
      if (out.length === targetSize) return out;
    }
    return out;
  };
  try {
    id = sampleId(size, alphabet, len, mask, step);
    if (id.length === size) return id;
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
  throw new RandomGenerationError(
    "Failed to generate secure string within safety limits.",
  );
}

export async function generateSecureId(length = 64): Promise<string> {
  validateNumericParam(length, "length", 1, 256);
  await ensureCrypto();
  return generateSecureStringSync(HEX_ALPHABET, length);
}

export function generateSecureIdSync(length = 64): string {
  validateNumericParam(length, "length", 1, 256);
  return generateSecureStringSync(HEX_ALPHABET, length);
}

/**
 * Async, yielding variant of secure string generation. Mirrors the sync algorithm
 * but yields back to the event loop between random byte batches to avoid long
 * blocking on the main thread. This is not a drop-in replacement for
 * generateSecureStringSync but provides similar guarantees with better
 * responsiveness in UI contexts.
 */
export async function generateSecureStringAsync(
  alphabet: string,
  size: number,
  options?: { signal?: AbortSignal },
): Promise<string> {
  const { len, mask, step } = computeAlphabetParams(alphabet, size);
  if (len === 1) return alphabet.repeat(size);

  let id = "";
  const crypto = await ensureCrypto();
  const bytes = new Uint8Array(step);
  const MAX_ITER = 500;
  try {
    for (let iter = 0; iter < MAX_ITER && id.length < size; iter++) {
      // Abort & visibility checks to preserve data integrity (§2.11)
      checkAbortOrHidden(options?.signal);
      crypto.getRandomValues(bytes);
      for (let i = 0; i < step && id.length < size; i++) {
        const charIndex = (bytes[i] as number) & mask;
        if (charIndex < len) id += alphabet[charIndex] as string;
      }
      if (id.length === size) return id;
      // Yield to event loop to keep UI responsive
      await Promise.resolve();
      // Check abort again after yielding
      checkAbortOrHidden(options?.signal);
    }
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
  throw new RandomGenerationError(
    "Failed to generate secure string within safety limits.",
  );
}

export async function generateSecureUUID(): Promise<string> {
  const crypto = await ensureCrypto();
  const cryptoWithUUID = crypto as Crypto & { randomUUID?: () => string };
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
    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  } finally {
    secureWipe(bytes, { forbidShared: true });
  }
}

// --- Key & Nonce Generation ---
type KeyUsageAlias = "encrypt" | "decrypt" | "wrapKey" | "unwrapKey";
type KeyUsagesArray = Array<KeyUsageAlias>;

const ALLOWED_KEY_USAGES = new Set<KeyUsageAlias>([
  "encrypt",
  "decrypt",
  "wrapKey",
  "unwrapKey",
]);

export async function createOneTimeCryptoKey(
  options: {
    lengthBits?: 128 | 256;
    /** @deprecated Use `lengthBits`. */
    length?: 128 | 256;
    usages?: KeyUsagesArray;
  } = {},
): Promise<CryptoKey> {
  const { lengthBits, usages = ["encrypt", "decrypt"] } = options;
  const deprecatedLength = (options as { length?: 128 | 256 }).length;
  let bitLength: number;

  if (lengthBits !== undefined && deprecatedLength !== undefined) {
    throw new InvalidParameterError(
      "Cannot specify both lengthBits and deprecated length.",
    );
  }
  if (deprecatedLength !== undefined && isDevelopment()) {
    secureDevLog(
      "warn",
      "security-kit",
      "DEPRECATION: `length` is deprecated. Use `lengthBits`.",
    );
  }

  bitLength = lengthBits ?? deprecatedLength ?? 256;
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
  const subtle = (crypto as { subtle?: SubtleCrypto }).subtle;
  if (!subtle) throw new CryptoUnavailableError("SubtleCrypto is unavailable.");

  const extractable = false;
  if (typeof subtle.generateKey === "function") {
    return subtle.generateKey(
      { name: "AES-GCM", length: bitLength },
      extractable,
      usages as KeyUsage[],
    );
  }

  const keyData = new Uint8Array(bitLength / 8);
  crypto.getRandomValues(keyData);
  try {
    return await subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM", length: bitLength },
      extractable,
      usages as KeyUsage[],
    );
  } finally {
    secureWipe(keyData, { forbidShared: true });
  }
}

export function createAesGcmNonce(byteLength = 12): Uint8Array {
  validateNumericParam(byteLength, "byteLength", 12, 16);
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

// --- Subresource Integrity (SRI) ---
export async function generateSRI(
  input: string | ArrayBuffer,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384",
): Promise<string> {
  const crypto = await ensureCrypto();
  const subtle = (crypto as { subtle?: SubtleCrypto }).subtle;
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
  if (input == null) {
    throw new InvalidParameterError(
      "Input content is required for SRI generation",
    );
  }

  // IMPORTANT: If callers pass a string here, JavaScript strings are immutable
  // and cannot be reliably wiped from memory. We therefore create an internal
  // Uint8Array copy which we wipe after use, but any original string data may
  // remain in memory and is not erasable. For sensitive secrets prefer passing
  // an ArrayBuffer or Uint8Array so callers can securely wipe the source buffer
  // after use.

  /**
   * @security-note
   * For sensitive content prefer passing an ArrayBuffer/Uint8Array so callers
   * can securely wipe the source buffer after use. Passing strings will leave
   * immutable copies in engine memory that cannot be zeroed.
   */
  let internalView: Uint8Array | null = null;
  let digest: ArrayBuffer | undefined;

  try {
    if (typeof input === "string") {
      // Create internal copy from string
      internalView = SHARED_ENCODER.encode(input);
    } else {
      // Create internal copy from ArrayBuffer to avoid mutating caller data
      const buf = input;
      internalView = new Uint8Array(buf.byteLength);
      internalView.set(new Uint8Array(buf));
    }

    digest = await subtle.digest(subtleAlgo, internalView as BufferSource);
    return `${algorithm}-${_arrayBufferToBase64(digest)}`;
  } finally {
    // Only wipe our internal copies, never mutate caller data
    if (digest) secureWipe(new Uint8Array(digest), { forbidShared: true });
    if (internalView) secureWipe(internalView, { forbidShared: true });
  }
}

// --- Simple API Object ---
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
