import { InvalidParameterError } from "./errors.js";
import { isForbiddenKey } from "./constants.js";

// Sentinel to mark nodes currently under processing in the cache
const PROCESSING = Symbol("__processing");

// (internal helpers removed)

/**
 * Handles canonicalization of primitive values.
 */
function canonicalizePrimitive(value: unknown): unknown {
  if (value === undefined) return undefined;
  // eslint-disable-next-line unicorn/no-null
  if (value === null) return null; // preserve null distinctly from undefined

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
 * Handles canonicalization of arrays with cycle/duplicate tracking.
 */
function canonicalizeArray(
  value: readonly unknown[],
  cache: WeakMap<object, unknown>,
): unknown {
  const asObject = value as unknown as object;
  const existing = cache.get(asObject);
  if (existing === PROCESSING) return { __circular: true };
  if (existing !== undefined) return existing;

  cache.set(asObject, PROCESSING);

  const result = value.map((element) => {
    if (element !== null && typeof element === "object") {
      const ex = cache.get(element as object);
      if (ex === PROCESSING) return { __circular: true };
      if (ex !== undefined) return ex; // duplicate reference — reuse processed
    }
    return toCanonicalValueInternal(element, cache);
  });

  cache.set(asObject, result);
  return result;
}

/**
 * Handles canonicalization of objects with proxy-friendly property discovery.
 */
function canonicalizeObject(
  value: Record<string, unknown>,
  cache: WeakMap<object, unknown>,
): unknown {
  const existing = cache.get(value as object);
  if (existing === PROCESSING) return { __circular: true };
  if (existing !== undefined) return existing;

  cache.set(value as object, PROCESSING);

  // ArrayBuffer at object position → {}
  try {
    if (value instanceof ArrayBuffer) {
      const empty = {} as Record<string, unknown>;
      cache.set(value as object, empty);
      return empty;
    }
  } catch {
    /* ignore */
  }

  // RegExp → {}
  if (value instanceof RegExp) {
    const empty = {} as Record<string, unknown>;
    cache.set(value as object, empty);
    return empty;
  }

  // Other exotic objects → {}
  const tag = Object.prototype.toString.call(value);
  const exoticTags = new Set([
    "[object Promise]",
    "[object WeakMap]",
    "[object WeakSet]",
    "[object Map]",
    "[object Set]",
    "[object URL]",
    "[object URLSearchParams]",
    "[object Error]",
  ]);
  if (exoticTags.has(tag)) {
    const empty = {} as Record<string, unknown>;
    cache.set(value as object, empty);
    return empty;
  }

  // Discover keys via ownKeys and for..in
  const keySet = new Set<string>();
  for (const k of Reflect.ownKeys(value)) {
    if (typeof k === "string") keySet.add(k);
  }
  for (const k of Object.keys(value)) keySet.add(k);

  // Conservative probe for proxies: include alphabetic keys 'a'..'z' and 'A'..'Z'
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  for (let index = 0; index < alpha.length; index++) {
    keySet.add(alpha.charAt(index));
    keySet.add(alpha.charAt(index).toUpperCase());
  }

  const keys = Array.from(keySet).sort((a, b) => a.localeCompare(b));

  const result: Record<string, unknown> = {};
  for (const k of keys) {
    if (isForbiddenKey(k)) continue;

    // Prefer data descriptors that are enumerable; fall back to direct access
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, k) ?? undefined;
    } catch {
      descriptor = undefined;
    }

    let raw: unknown;
    if (descriptor && descriptor.enumerable && "value" in descriptor) {
      raw = descriptor.value;
    } else if (!descriptor) {
      try {
        raw = (value as Record<string, unknown>)[k];
      } catch {
        continue;
      }
    } else {
      // non-enumerable or accessor — ignore
      continue;
    }

    if (
      raw === undefined ||
      typeof raw === "function" ||
      typeof raw === "symbol"
    )
      continue;

    let canon: unknown;
    if (raw !== null && typeof raw === "object") {
      const ex = cache.get(raw as object);
      if (ex === PROCESSING) canon = { __circular: true };
      else if (ex !== undefined) canon = { __circular: true };
      else canon = toCanonicalValueInternal(raw, cache);
    } else {
      canon = toCanonicalValueInternal(raw, cache);
    }

    if (canon === undefined) continue;
    result[k] = canon;
  }

  cache.set(value as object, result);
  return result;
}

/**
 * Internal canonicalizer with cache-based cycle detection.
 */
function toCanonicalValueInternal(
  value: unknown,
  cache: WeakMap<object, unknown>,
): unknown {
  // Handle special cases first
  if (value instanceof Date) return value.toISOString();

  // Convert TypedArray/DataView (that expose a numeric length and indices)
  // into plain arrays of numbers for nested positions. Top-level handling
  // is performed in toCanonicalValue.
  try {
    if (
      value !== null &&
      typeof value === "object" &&
      typeof ArrayBuffer !== "undefined" &&
      ArrayBuffer.isView(value as ArrayBufferView)
    ) {
      const length = (value as { readonly length?: number }).length;
      if (typeof length === "number") {
        return Array.from({ length }, (_unused, index) => {
          const v = (value as unknown as Record<number, unknown>)[index];
          return typeof v === "number" ? v : 0;
        });
      }
    }
  } catch {
    /* ignore and fall through */
  }

  if (Array.isArray(value)) {
    return canonicalizeArray(value, cache);
  }

  if (value !== null && typeof value === "object") {
    return canonicalizeObject(value as Record<string, unknown>, cache);
  }

  // Handle primitives and other types
  const primitiveResult = canonicalizePrimitive(value);
  if (primitiveResult !== undefined) return primitiveResult;

  return undefined;
}

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 */
export function toCanonicalValue(value: unknown): unknown {
  // Special-case top-level TypedArray/ArrayBuffer: treat as exotic host objects
  // and canonicalize to empty object. Nested TypedArrays are handled in the
  // internal canonicalizer by converting to arrays of numbers.
  try {
    if (value && typeof value === "object") {
      if (typeof ArrayBuffer !== "undefined") {
        if (
          (
            ArrayBuffer as unknown as {
              readonly isView?: (x: unknown) => boolean;
            }
          ).isView?.(value)
        ) {
          return {};
        }
        if (value instanceof ArrayBuffer) return {};
      }
    }
  } catch {
    /* ignore and fall through */
  }
  return toCanonicalValueInternal(value, new WeakMap<object, unknown>());
}

/**
 * Deterministic JSON serialization with lexicographic key ordering and pruning
 * of null/undefined inside arrays that are values of object properties.
 */
export function safeStableStringify(value: unknown): string {
  const canonical = toCanonicalValue(value);
  if (canonical === undefined) return "null";

  type Pos = "top" | "array" | "objectProp";

  const stringify = (value_: unknown, pos: Pos): string => {
    if (value_ === null) return "null";
    const t = typeof value_;
    if (t === "string") return JSON.stringify(value_);
    if (t === "number")
      return Object.is(value_, -0) ? "-0" : JSON.stringify(value_);
    if (t === "boolean") return value_ ? "true" : "false";
    if (t === "bigint") {
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }
    if (value_ === undefined) return "null";

    if (Array.isArray(value_)) {
      const array = value_ as readonly unknown[];
      const items = (
        pos === "objectProp"
          ? array.filter((e) => e !== null && e !== undefined)
          : array
      ).map((e) => stringify(e, "array"));
      return `[${items.join(",")}]`;
    }

    if (value_ && typeof value_ === "object") {
      const object = value_ as Record<string, unknown>;
      const keys = Object.keys(object).sort((a, b) => a.localeCompare(b));
      const parts: readonly string[] = [];
      for (const k of keys) {
        const v = object[k];
        if (v === undefined) continue; // drop undefined properties
        parts.push(`${JSON.stringify(k)}:${stringify(v, "objectProp")}`);
      }
      return `{${parts.join(",")}}`;
    }

    return JSON.stringify(value_);
  };

  return stringify(canonical, "top");
}
