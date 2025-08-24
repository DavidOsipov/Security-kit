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
import { ensureCrypto, ensureCryptoSync } from "./state";
import { isDevelopment } from "./environment";
import {
  secureWipe,
  validateNumericParam,
  validateProbability,
  _arrayBufferToBase64,
  secureCompare,
  secureCompareAsync,
} from "./utils";

const ENCODER = new TextEncoder();

// --- Constants ---
export const URL_ALPHABET =
  "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
const HEX_ALPHABET = "0123456789abcdef";

// --- Random Data Generation ---
export function getSecureRandomBytesSync(length = 1): Uint8Array {
  validateNumericParam(length, "length", 1, 4096);
  const crypto = ensureCryptoSync();
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export async function getSecureRandomAsync(): Promise<number> {
  const crypto = await ensureCrypto();
  if (typeof BigUint64Array !== "undefined") {
    try {
      const buffer = new BigUint64Array(1);
      crypto.getRandomValues(buffer);
      const value = buffer[0];
      if (value === undefined)
        throw new CryptoUnavailableError("Failed to generate random value.");
      return Number(value >> BigInt(12)) / 2 ** 52;
    } catch {
      /* Fall through */
    }
  }
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export function getSecureRandom(): number {
  const crypto = ensureCryptoSync();
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) / (0xffffffff + 1);
}

export async function getSecureRandomInt(
  min: number,
  max: number,
): Promise<number> {
  const MAX_SAFE_RANGE = 2 ** 31;
  validateNumericParam(min, "min", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  validateNumericParam(max, "max", -MAX_SAFE_RANGE, MAX_SAFE_RANGE);
  if (min > max)
    throw new InvalidParameterError("min must be less than or equal to max.");
  if (min === max) return min;

  const crypto = await ensureCrypto();
  const rangeBig = BigInt(max) - BigInt(min) + BigInt(1);

  if (rangeBig <= BigInt(0x100000000)) {
    const range = Number(rangeBig);
    const arr = new Uint32Array(1);
    const threshold = Math.floor(0x100000000 / range) * range;
    try {
      for (let i = 0; i < 1000; i++) {
        // Reduced iteration limit for typical cases
        crypto.getRandomValues(arr);
        const r = (arr[0] ?? 0) >>> 0;
        if (r < threshold) return min + (r % range);
      }
    } finally {
      secureWipe(arr);
    }
  } else if (typeof BigUint64Array !== "undefined") {
    const arr64 = new BigUint64Array(1);
    const space = BigInt(1) << BigInt(64);
    const threshold64 = space - (space % rangeBig);
    try {
      for (let i = 0; i < 1000; i++) {
        crypto.getRandomValues(arr64);
        const r = arr64[0];
        if (r !== undefined && r < threshold64)
          return min + Number(r % rangeBig);
      }
    } finally {
      secureWipe(arr64);
    }
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
  if (new Set(alphabet).size !== alphabet.length) {
    throw new InvalidParameterError(
      "Alphabet must contain only unique characters.",
    );
  }
  const len = alphabet.length;
  if (len === 1) return alphabet.repeat(size);

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

  let id = "";
  const crypto = ensureCryptoSync();
  const bytes = new Uint8Array(step);
  try {
    for (let iter = 0; iter < 1000; iter++) {
      crypto.getRandomValues(bytes);
      for (let i = 0; i < step; i++) {
        const charIndex = (bytes[i] as number) & mask;
        if (charIndex < len) {
          id += alphabet[charIndex] as string;
          if (id.length === size) return id;
        }
      }
    }
  } finally {
    secureWipe(bytes);
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
    secureWipe(bytes);
  }
}

// --- Key & Nonce Generation ---
type KeyUsageAlias = "encrypt" | "decrypt" | "wrapKey" | "unwrapKey";

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
    usages?: Array<"encrypt" | "decrypt" | "wrapKey" | "unwrapKey">;
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
    console.warn(
      "[security-kit] DEPRECATION: `length` is deprecated. Use `lengthBits`.",
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
      { name: "AES-GCM" },
      extractable,
      usages as KeyUsage[],
    );
  } finally {
    secureWipe(keyData);
  }
}

export function createAesGcmNonce(byteLength = 12): Uint8Array {
  validateNumericParam(byteLength, "byteLength", 12, 16);
  return getSecureRandomBytesSync(byteLength);
}

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

  const isString = typeof input === "string";
  const dataForDigest = isString ? ENCODER.encode(input) : input;
  let digest: ArrayBuffer | undefined;
  try {
    digest = await subtle.digest(subtleAlgo, dataForDigest);
    return `${algorithm}-${_arrayBufferToBase64(digest)}`;
  } finally {
    if (digest) secureWipe(new Uint8Array(digest));
    if (isString) secureWipe(dataForDigest as Uint8Array);
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
