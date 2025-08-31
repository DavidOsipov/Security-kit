// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Feature detection helpers for cryptographic capabilities.
 * This module provides synchronous and asynchronous checks for
 * Web Crypto API features across different JavaScript runtimes.
 */

export function hasRandomUUIDSync(): boolean {
  const c = (globalThis as { readonly crypto?: Crypto }).crypto as
    | (Crypto & { readonly randomUUID?: () => string })
    | undefined;
  return Boolean(c?.randomUUID && typeof c.randomUUID === "function");
}

export function getCryptoCapabilities(): Readonly<{
  readonly hasSyncCrypto: boolean;
  readonly hasSubtle: boolean;
  readonly hasDigest: boolean;
  readonly hasRandomUUIDSync: boolean;
  readonly hasRandomUUIDAsyncLikely: boolean;
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
