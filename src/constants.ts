// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Project-wide immutable constants and accessors.
 * Keep security-sensitive collections private and expose read-only accessors
 * to prevent runtime mutation by consumers.
 */

const _FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
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
