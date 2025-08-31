import { InvalidParameterError } from "./errors.js";
import { isForbiddenKey } from "./constants.js";

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 *
 * TRANSFORMATION RULES (project uses undefined for elision):
 * - null → null (preserved distinctly from undefined)
 * - undefined → undefined (elided when inside objects/arrays as appropriate)
 * - Finite numbers → unchanged
 * - Non-finite numbers (NaN, Infinity) → undefined
 * - Strings/booleans → unchanged
 * - BigInt → throws InvalidParameterError (not JSON-serializable)
 * - Dates → ISO string
 * - Arrays → recursively canonicalized, order preserved
 * - Objects → recursively canonicalized with sorted keys, forbidden keys filtered
 * - Functions/Symbols → undefined
 * - Other types → String(value)
 *
 * @param value - The value to canonicalize
 * @returns Canonical representation safe for JSON.stringify
 * @throws InvalidParameterError for BigInt values (not JSON-serializable)
 */
/**
 * Handles canonicalization of primitive values.
 */
function canonicalizePrimitive(value: unknown): unknown {
  if (value === undefined) return undefined;
  // eslint-disable-next-line unicorn/no-null
  if (value === null) return null; // Security: preserve null distinctly from undefined

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

  return value; // fallback for other types
}

/**
 * Handles canonicalization of arrays.
 */
function canonicalizeArray(
  value: readonly unknown[],
  visited: WeakSet<object>,
): unknown {
  return value.map((element) => toCanonicalValueInternal(element, visited));
}

/**
 * Handles canonicalization of objects.
 */
function canonicalizeObject(
  value: Record<string, unknown>,
  visited: WeakSet<object>,
): unknown {
  if (visited.has(value)) {
    return { __circular: true };
  }
  visited.add(value);

  const keys = Object.keys(value).sort((a, b) => a.localeCompare(b));

  // Allocate result object once and assign properties to avoid O(n²) spread operations
  const result: Record<string, unknown> = {};
  for (const k of keys) {
    // Use centralized forbidden key check instead of hardcoded list
    if (isForbiddenKey(k)) continue;

    const v = value[k];
    if (v === undefined || typeof v === "function" || typeof v === "symbol") {
      continue;
    }

    const canonicalV = toCanonicalValueInternal(v, visited);
    if (canonicalV === undefined) continue;

    // eslint-disable-next-line functional/immutable-data
    result[k] = canonicalV;
  }
  visited.delete(value);
  return result;
}

/**
 * Internal canonicalizer that carries a visited set for cycle detection.
 */
function toCanonicalValueInternal(
  value: unknown,
  visited: WeakSet<object>,
): unknown {
  // Handle special cases first
  if (value instanceof Date) return value.toISOString();

  if (Array.isArray(value)) {
    return canonicalizeArray(value, visited);
  }

  if (value !== null && typeof value === "object") {
    return canonicalizeObject(value as Record<string, unknown>, visited);
  }

  // Handle primitives and other types
  const primitiveResult = canonicalizePrimitive(value);
  if (primitiveResult !== undefined) return primitiveResult;

  return undefined;
}

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 *
 * TRANSFORMATION RULES:
 * - null → null (preserved distinctly from undefined)
 * - undefined → undefined
 * - Finite numbers → unchanged
 * - Non-finite numbers (NaN, Infinity) → undefined
 * - Strings/booleans → unchanged
 * - BigInt → throws InvalidParameterError (not JSON-serializable)
 * - Dates → ISO string
 * - Arrays → recursively canonicalized, order preserved
 * - Objects → recursively canonicalized with sorted keys, forbidden keys filtered
 * - Functions/Symbols → undefined
 *
 * @param value - The value to canonicalize
 * @returns Canonical representation safe for JSON.stringify
 * @throws InvalidParameterError for BigInt values (not JSON-serializable)
 */
export function toCanonicalValue(value: unknown): unknown {
  return toCanonicalValueInternal(value, new WeakSet());
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
