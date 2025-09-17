// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Project-wide immutable constants and accessors.
 * Keep security-sensitive collections private and expose read-only accessors
 * to prevent runtime mutation by consumers.
 */

const _FORBIDDEN_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);
Object.freeze(_FORBIDDEN_KEYS);

/**
 * Returns true if the provided key is considered forbidden for object properties
 * (e.g., to prevent prototype pollution).
 */
export function isForbiddenKey(key: string): boolean {
  return _FORBIDDEN_KEYS.has(key);
}

/**
 * Returns a copy of forbidden keys as an array for diagnostic or display purposes.
 * Returns a shallow copy to avoid exposing internal Set for mutation.
 */
export function getForbiddenKeys(): readonly string[] {
  return Array.from(_FORBIDDEN_KEYS);
}

// --- Handshake / Nonce defaults ---
/** Default maximum nonce length accepted for handshakes (characters) */
export const DEFAULT_HANDSHAKE_MAX_NONCE_LENGTH = 1024;

/** Supported nonce encoding formats */
export const NONCE_FORMAT_BASE64 = "base64" as const;
export const NONCE_FORMAT_BASE64URL = "base64url" as const;
export const NONCE_FORMAT_HEX = "hex" as const;

export type NonceFormat =
  | typeof NONCE_FORMAT_BASE64
  | typeof NONCE_FORMAT_BASE64URL
  | typeof NONCE_FORMAT_HEX;

export const DEFAULT_NONCE_FORMATS: readonly NonceFormat[] = [
  NONCE_FORMAT_BASE64,
  NONCE_FORMAT_BASE64URL,
];
