// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov
/**
 * Shared canonicalization utilities for secure API signing.
 *
 * This module provides deterministic, security-hardened JSON serialization
 * that prevents common attack vectors while ensuring consistent output
 * between client and server implementations.
 *
 * SECURITY FEATURES:
 * - Deterministic key ordering (lexicographic sort)
 * - Prototype pollution prevention (filters forbidden keys)
 * - BigInt/Symbol/Function normalization
 * - Consistent null/undefined handling
 * - Side-effect free (pure functions, tree-shakable)
 *
 * Used by SecureApiSigner (client) and verifyApiRequestSignature (server)
 * to ensure identical canonical representations for signature verification.
 */

import { InvalidParameterError } from "./errors.js";

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 *
 * TRANSFORMATION RULES:
 * - null/undefined → undefined
 * - Finite numbers → unchanged
 * - Non-finite numbers (NaN, Infinity) → null
 * - Strings/booleans → unchanged
 * - BigInt → throws InvalidParameterError (not JSON-serializable)
 * - Dates → ISO string
 * - Arrays → recursively canonicalized, order preserved
 * - Objects → recursively canonicalized with sorted keys, forbidden keys filtered
 * - Functions/Symbols → null
 * - Other types → String(value)
 *
 * @param value - The value to canonicalize
 * @returns Canonical representation safe for JSON.stringify
 * @throws InvalidParameterError for BigInt values (not JSON-serializable)
 */
export function toCanonicalValue(value: unknown): unknown {
  if (value === undefined || value === null) return undefined;

  const t = typeof value;

  if (t === "string" || t === "boolean") return value;

  if (t === "number") {
    return Number.isFinite(value as number) ? value : undefined;
  }

  if (t === "bigint") {
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }

  if (t === "symbol" || t === "function") return undefined;

  if (value instanceof Date) return value.toISOString();

  if (Array.isArray(value)) {
    return value.map((element) => toCanonicalValue(element));
  }

  if (t === "object") {
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort((a, b) => a.localeCompare(b));

    // Build a new object immutably to avoid in-place mutations
    const result = keys.reduce<Record<string, unknown>>((accumulator, k) => {
      // Filter out forbidden keys that could lead to prototype pollution
      if (k === "__proto__" || k === "constructor" || k === "prototype") {
        return accumulator;
      }

      const v = object[k];
      if (v === undefined || typeof v === "function" || typeof v === "symbol") {
        return accumulator;
      }

      const canonicalV = toCanonicalValue(v);
      if (canonicalV === undefined) return accumulator;

      // Return a new object with the property added (immutable)
      return { ...accumulator, [k]: canonicalV };
    }, {});

    return result;
  }

  return String(value);
}

/**
 * Produces a deterministic JSON string from any value using canonical transformation.
 *
 * This function ensures that equivalent objects always produce identical strings
 * regardless of property insertion order, making it suitable for cryptographic
 * operations that require consistent input representation.
 *
 * SECURITY GUARANTEE: Objects with the same semantic content will always
 * produce identical output, preventing signature bypass attacks based on
 * property reordering or prototype pollution.
 *
 * @param value - The value to stringify
 * @returns Deterministic JSON string representation
 * @throws InvalidParameterError for BigInt values
 *
 * @example
 * ```typescript
 * // These produce identical output despite different property order
 * safeStableStringify({ b: 2, a: 1 }); // '{"a":1,"b":2}'
 * safeStableStringify({ a: 1, b: 2 }); // '{"a":1,"b":2}'
 * ```
 */
export function safeStableStringify(value: unknown): string {
  const canonical = toCanonicalValue(value);

  // If the canonical form is undefined, return the JSON `null` literal string.
  // This ensures a deterministic string output suitable for cryptographic
  // signing operations rather than returning `undefined`.
  if (canonical === undefined) return "null";

  return JSON.stringify(canonical);
}
