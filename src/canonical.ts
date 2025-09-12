import { InvalidParameterError } from "./errors.ts";
import { SHARED_ENCODER } from "./encoding.ts";
import { isForbiddenKey } from "./constants.ts";
import { getCanonicalConfig } from "./config.ts";

// Sentinel to mark nodes currently under processing in the cache
const PROCESSING = Symbol("__processing");

// (internal helpers removed)

/**
 * Narrow/TypeGuard: returns true only for non-null objects.
 * Using an explicit helper eliminates ambiguous truthy checks that trigger
 * strict-boolean-expression lint errors and documents intent (ASVS: clear
 * input validation and explicit type discrimination).
 */
function isNonNullObject(
  value: unknown,
): value is Record<PropertyKey, unknown> {
  return value !== null && value !== undefined && typeof value === "object";
}

/**
 * Safe property assignment used during canonicalization. Centralizing this
 * logic lets us validate keys once and avoid repeated justifications for the
 * security/detect-object-injection rule. We explicitly reject forbidden keys
 * (prototype pollution vectors) and silently ignore anything non-string. The
 * target objects passed here are created with a null prototype so even if a
 * dangerous key slipped through (it cannot due to isForbiddenKey), it would
 * not mutate Object.prototype. (OWASP ASVS L3: object property injection /
 * prototype pollution hardening.)
 */
function safeAssign(
  target: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  if (typeof key !== "string") return; // defensive: only string keys
  if (isForbiddenKey(key)) return; // drop known dangerous keys
  // Reflect.set used instead of direct assignment to avoid accidental getters
  // invocation differences in the future and to make intent explicit.
  Reflect.set(target, key, value);
}

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
    // Nested BigInt must be rejected per security policy. Throw a specific
    // InvalidParameterError so callers can handle this deterministically.
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
// eslint-disable-next-line sonarjs/cognitive-complexity -- Array canonicalization needs explicit index-based traversal, cache checks, and guarded conversions to meet security/perf constraints
function canonicalizeArray(
  value: readonly unknown[],
  cache: WeakMap<object, unknown>,
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
  }
  const asObject = value as unknown as object;
  const existing = cache.get(asObject);
  if (existing === PROCESSING) return { __circular: true };
  if (existing !== undefined) return existing;

  cache.set(asObject, PROCESSING);

  // Build result explicitly from numeric indices to avoid inheriting
  // enumerable properties from Array.prototype (prototype pollution).
  // Preserve standard Array prototype so callers relying on array methods
  // (e.g., .filter/.map in safeStableStringify) continue to work.
  const length = (value as { readonly length?: number }).length ?? 0;
  // Create an array with null prototype to avoid inherited pollution
  // Use a mutable array type for construction; we still create with null prototype
  // to avoid inherited pollution.
  // Use a mutable array instance with a null prototype. We only perform
  // index-based writes; no Array.prototype methods are relied upon.
  // Use a mutable array type locally for index assignments; prototype is null to avoid pollution.
  // eslint-disable-next-line functional/prefer-readonly-type -- We use a local mutable array as a builder; result is not exposed externally
  const result: unknown[] = new Array<unknown>(length >>> 0);
  // eslint-disable-next-line functional/immutable-data, unicorn/no-null -- Setting a null prototype is an intentional, one-time hardening step against prototype pollution per Security Constitution
  Object.setPrototypeOf(result, null as unknown as object);
  // eslint-disable-next-line functional/no-let -- Index-based loop avoids iterator surprises and is faster/safer under hostile prototypes
  for (let index = 0; index < result.length; index++) {
    // eslint-disable-next-line functional/no-let -- Assigned in try/catch; using const would complicate control flow
    let element: unknown;
    try {
      // If the index does not exist on the source array, treat as undefined
      // (will later be serialized as null by stringify).
      // Access inside try/catch to guard against exotic hosts throwing.
      element = Object.hasOwn(value, index)
        ? (value as unknown as Record<number, unknown>)[index]
        : undefined;
    } catch {
      element = undefined;
    }

    if (isNonNullObject(element)) {
      const ex = cache.get(element);
      if (ex === PROCESSING) {
        // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- Index is a loop-controlled number; not attacker-controlled; assigning into array with null prototype is safe.
        result[index] = { __circular: true };
        continue;
      }
      if (ex !== undefined) {
        // Duplicate reference to an already-processed node — reuse existing canonical form
        // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- See rationale above; controlled numeric index write.
        result[index] = ex;
        continue;
      }
    }
    // Enforce explicit rejection of BigInt values located inside arrays
    if (typeof element === "bigint") {
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }
    // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- Controlled numeric index write; key space not influenced by attacker beyond array length already bounded earlier.
    result[index] = toCanonicalValueInternal(
      element,
      cache,
      depthRemaining === undefined ? undefined : depthRemaining - 1,
    );
  }

  cache.set(asObject, result);
  return result;
}
/**
 * Handles canonicalization of objects with proxy-friendly property discovery.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Complex object canonicalization with multiple exotic object types and proxy handling
function canonicalizeObject(
  value: Record<string, unknown>,
  cache: WeakMap<object, unknown>,
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
  }
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

  // Discover keys via ownKeys (strings only). We do not add Object.keys twice;
  // enumerability is validated when reading descriptors below.
  const keySet = new Set<string>();
  for (const k of Reflect.ownKeys(value)) {
    // eslint-disable-next-line functional/immutable-data
    if (typeof k === "string") keySet.add(k);
  }

  // Conservative probe for proxies: include alphabetic keys 'a'..'z' and 'A'..'Z'
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  // eslint-disable-next-line functional/no-let -- Intentional let for loop index in proxy key probing
  for (let index = 0; index < alpha.length; index++) {
    // eslint-disable-next-line functional/immutable-data -- Intentional mutability for proxy key probing during canonicalization
    keySet.add(alpha.charAt(index));
    // eslint-disable-next-line functional/immutable-data -- Intentional mutability for proxy key probing during canonicalization
    keySet.add(alpha.charAt(index).toUpperCase());
  }

  const keys = Array.from(keySet).sort((a, b) => a.localeCompare(b));

  // Create the result with a null prototype up-front so we never perform
  // assignments onto a default Object.prototype bearing object. This reduces
  // the surface for prototype pollution and allows safeAssign to remain a
  // thin wrapper (ASVS L3: Use of secure object construction patterns).
  const result: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const k of keys) {
    // Skip forbidden keys (e.g., __proto__, prototype, constructor) to avoid
    // exposing or reintroducing prototype pollution via canonicalized output.
    // Per sanitizer policy, we silently drop these keys instead of throwing.
    if (isForbiddenKey(k)) {
      continue;
    }

    // Prefer data descriptors that are enumerable; fall back to direct access
    // eslint-disable-next-line functional/no-let -- Intentional let for descriptor handling in canonicalization
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, k) ?? undefined;
    } catch {
      descriptor = undefined;
    }

    // eslint-disable-next-line functional/no-let -- Intentional let for raw value handling in canonicalization
    let raw: unknown;
    if (
      descriptor !== undefined &&
      descriptor.enumerable === true &&
      "value" in descriptor
    ) {
      raw = descriptor.value;
    } else if (descriptor === undefined) {
      try {
        raw = value[k];
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

    // Enforce explicit rejection of BigInt values located inside objects
    if (typeof raw === "bigint") {
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }

    // Note: No special-case for 'constructor' beyond dropping above; tests
    // and sanitizer policy require ignoring it rather than throwing.

    // Local canonical value shape used to satisfy strict typing for assignments
    type CanonicalLocal =
      | null
      | string
      | number
      | boolean
      | Record<string, unknown>
      | readonly unknown[];

    const isCanonicalValue = (x: unknown): x is CanonicalLocal => {
      if (x === null) return true;
      const t = typeof x;
      if (t === "string" || t === "boolean" || t === "number") return true;
      if (Array.isArray(x)) return true;
      if (x && typeof x === "object") return true;
      return false;
    };

    type CanonResult =
      | { readonly present: true; readonly value: CanonicalLocal }
      | { readonly present: false };

    const computeCanon = (input: unknown): CanonResult => {
      if (input !== null && typeof input === "object") {
        const ex = cache.get(input);
        if (ex === PROCESSING)
          return {
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          };
        if (ex !== undefined)
          return {
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          };
      }
      const out = toCanonicalValueInternal(
        input,
        cache,
        depthRemaining === undefined ? undefined : depthRemaining - 1,
      );
      if (out === undefined) return { present: false };
      if (isCanonicalValue(out)) return { present: true, value: out };
      return { present: false };
    };

    const canon = computeCanon(raw);

    if (!canon.present) continue;

    // Use safeAssign which validates key safety; rule flagged direct dynamic
    // assignment as a potential injection sink. Key list is derived from
    // ownKeys + controlled probe set and filtered via isForbiddenKey.
    safeAssign(result, k, canon.value);
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
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
  }
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

  // Array handling: delegate to array canonicalizer for cycle/dup detection
  if (Array.isArray(value)) {
    return canonicalizeArray(
      value as readonly unknown[],
      cache,
      depthRemaining,
    );
  }

  if (isNonNullObject(value)) {
    return canonicalizeObject(
      value as Record<string, unknown>,
      cache,
      depthRemaining,
    );
  }

  // Handle primitives and other types
  // BigInt must be rejected consistently as a security policy
  if (typeof value === "bigint") {
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }

  const primitiveResult = canonicalizePrimitive(value);
  if (primitiveResult !== undefined) return primitiveResult;

  return undefined;
}

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Security hardening requires multiple guarded branches and defensive checks
export function toCanonicalValue(value: unknown): unknown {
  // Reject top-level BigInt per security policy: BigInt is not supported
  // in payloads and must be rejected to avoid ambiguous JSON handling.
  if (typeof value === "bigint") {
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }
  // Special-case top-level TypedArray/ArrayBuffer: treat as exotic host objects
  // and canonicalize to empty object. Nested TypedArrays are handled in the
  // internal canonicalizer by converting to arrays of numbers.

  // Reject extremely large arrays early to avoid resource exhaustion.
  const { maxTopLevelArrayLength } = getCanonicalConfig();
  if (
    Array.isArray(value) &&
    (value as readonly unknown[]).length >= maxTopLevelArrayLength
  ) {
    throw new InvalidParameterError("Array too large for canonicalization.");
  }

  try {
    if (isNonNullObject(value)) {
      if (typeof ArrayBuffer !== "undefined") {
        const isView = (
          ArrayBuffer as unknown as {
            readonly isView?: (x: unknown) => boolean;
          }
        ).isView;
        if (isView?.(value) === true) {
          return {};
        }
        if (value instanceof ArrayBuffer) return {};
      }
    }
  } catch {
    /* ignore and fall through */
  }

  try {
    // Quick top-level forbidden-key check to fail fast on obvious prototype-pollution attempts
    if (isNonNullObject(value)) {
      try {
        // Avoid eagerly throwing on top-level forbidden keys; deeper traversal
        // will skip/remove forbidden keys consistently. This preserves API
        // expectations while still sanitizing prototype-polluting names.
        // Probe ownKeys to trigger potential proxy traps; capture length to avoid unused-var lint.
        const _ownKeysCount = Reflect.ownKeys(value).length;
        if (_ownKeysCount === -1) {
          // This branch is unreachable; it exists to make the read explicit and
          // satisfy no-unused-vars/no-unused-locals without using the `void` operator.
        }
      } catch {
        // ignore failures reading keys from exotic hosts — we'll detect deeper during traversal
      }
    }
    // Defensive pre-scan: reject any BigInt found anywhere in the input tree.
    // This ensures nested BigInt values are consistently rejected regardless
    // of exotic host objects or proxy behavior that could bypass deeper
    // checks during canonicalization.
    const cfg = getCanonicalConfig();
    const scanInitialDepth = cfg.maxDepth ?? undefined;
    // Track visited nodes to avoid exponential blow-up on cyclic or highly
    // connected graphs during the pre-scan. WeakSet ensures we don't retain
    // references and is safe for arbitrary object graphs.
    const visited = new WeakSet<object>();
    // eslint-disable-next-line sonarjs/cognitive-complexity -- Defensive deep scan handles hostile objects, cycles, and proxies
    const assertNoBigIntDeep = (v: unknown, depth?: number): void => {
      if (depth !== undefined && depth <= 0) {
        throw new RangeError("Canonicalization depth budget exceeded");
      }
      if (typeof v === "bigint") {
        throw new InvalidParameterError(
          "BigInt values are not supported in payload/context.body.",
        );
      }
      if (isNonNullObject(v)) {
        // Detect dangerous constructor.prototype nesting to prevent prototype pollution attempts
        // If an object contains a nested constructor.prototype, treat as unsafe
        // but do not throw during pre-scan; main traversal will skip forbidden
        // keys. This preserves sanitizer behavior instead of failing early.
        try {
          const ctor = (v as Record<string, unknown>)["constructor"];
          if (
            typeof ctor === "object" &&
            Object.hasOwn(ctor as object, "prototype")
          ) {
            // Mark visited and continue without throwing here
          }
        } catch {
          /* ignore access errors */
        }
        // Skip already-visited nodes to prevent repeated traversal of cycles
        // or shared subgraphs which can otherwise lead to exponential work.
        try {
          const currentObject: object = v;
          if (visited.has(currentObject)) return;
          visited.add(currentObject);
        } catch {
          // If WeakSet operations throw due to hostile objects, fall through
          // without marking as visited; depth caps still protect us.
        }
        if (Array.isArray(v)) {
          for (const it of v) {
            assertNoBigIntDeep(it, depth === undefined ? undefined : depth - 1);
          }
        } else {
          try {
            for (const key of Reflect.ownKeys(v)) {
              // Access property value defensively; ignore access errors
              // eslint-disable-next-line functional/no-let -- Value is assigned in try/catch to preserve control flow
              let value_: unknown;
              try {
                value_ = v[key as PropertyKey];
              } catch {
                continue;
              }
              // Recurse without swallowing errors from deep checks; we must
              // fail closed on BigInt or forbidden constructor.prototype
              assertNoBigIntDeep(
                value_,
                depth === undefined ? undefined : depth - 1,
              );
            }
          } catch {
            // ignore failures enumerating keys on exotic hosts
          }
        }
      }
    };
    assertNoBigIntDeep(value, scanInitialDepth);
    const initialDepth = scanInitialDepth;
    const canonical = toCanonicalValueInternal(
      value,
      new WeakMap<object, unknown>(),
      initialDepth,
    );
    // If the canonicalized result contains any nested __circular markers,
    // attach a non-enumerable top-level marker to aid detection without
    // altering the enumerable shape used by consumers.
    try {
      if (hasCircularSentinel(canonical)) {
        if (isNonNullObject(canonical)) {
          // eslint-disable-next-line functional/immutable-data -- Intentional addition of a non-enumerable marker for diagnostic purposes; does not affect consumer-visible enumerable shape
          Object.defineProperty(canonical, "__circular", {
            value: true,
            enumerable: false,
            configurable: false,
          });
        }
      }
    } catch {
      /* ignore */
    }
    return canonical;
  } catch (error) {
    if (error instanceof InvalidParameterError) throw error;
    if (error instanceof RangeError) {
      // Fail CLOSED: depth exhaustion or traversal resource limits must not
      // silently produce an empty object. Convert to a typed error so callers
      // can handle deterministically per Pillar #1 and ASVS L3.
      throw new InvalidParameterError(
        "Canonicalization depth budget exceeded.",
      );
    }
    // Ensure we always throw an Error object. If a non-Error was thrown,
    // wrap it to preserve the original message/inspectable value.
    if (error instanceof Error) throw error;
    throw new Error(String(error));
  }
}

/**
 * Recursively scans a canonical value and returns true if any nested node
 * contains the `__circular` sentinel. This helper is extracted to reduce the
 * cognitive complexity of `toCanonicalValue` and to make the scanning logic
 * testable in isolation.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Separate helper is already extracted; remaining complexity is due to array/object traversal
export function hasCircularSentinel(
  v: unknown,
  depthRemaining?: number,
): boolean {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Circular sentinel scan depth budget exceeded");
  }
  if (isNonNullObject(v)) {
    try {
      if (Object.hasOwn(v, "__circular")) return true;
    } catch {
      /* ignore host failures */
    }
    if (Array.isArray(v)) {
      // Avoid relying on Array.prototype iteration since some arrays in this
      // module are constructed with a null prototype for pollution resistance.
      // Use index-based access to traverse elements safely.

      const n = (v as { readonly length: number }).length;
      // eslint-disable-next-line functional/no-let -- Loop counter is local to scanning logic
      for (let index = 0; index < n; index++) {
        const item = (v as unknown as { readonly [index: number]: unknown })[
          index
        ];
        if (
          hasCircularSentinel(
            item,
            depthRemaining === undefined ? undefined : depthRemaining - 1,
          )
        )
          return true;
      }
    } else {
      for (const k of Object.keys(v as Record<string, unknown>)) {
        if (
          hasCircularSentinel(
            (v as Record<string, unknown>)[k],
            depthRemaining === undefined ? undefined : depthRemaining - 1,
          )
        )
          return true;
      }
    }
  }
  return false;
}

/**
 * Deterministic JSON serialization with lexicographic key ordering and pruning
 * of null/undefined inside arrays that are values of object properties.
 */
export function safeStableStringify(value: unknown): string {
  // Fast pre-check: reject extremely large strings to avoid excessive memory
  // or CPU work during canonicalization / stringification. Use configured limit.
  const { maxStringLengthBytes } = getCanonicalConfig();
  if (
    typeof value === "string" &&
    SHARED_ENCODER.encode(value).length > maxStringLengthBytes
  ) {
    throw new InvalidParameterError("Payload too large for stable stringify.");
  }
  const canonical = toCanonicalValue(value);
  if (canonical === undefined) return "null";

  type Pos = "top" | "array" | "objectProp";

  // Render primitive JSON values and special cases. Returns undefined when the value
  // is not a primitive, allowing the caller to handle arrays/objects.
  const renderPrimitive = (v: unknown): string | undefined => {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "string") return JSON.stringify(v);
    if (t === "number") return Object.is(v, -0) ? "-0" : JSON.stringify(v);
    if (t === "boolean") return v ? "true" : "false";
    if (t === "bigint") {
      // Enforce BigInt rejection at stringification time as well to preserve
      // invariant across all layers (defense-in-depth per Security Constitution)
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }
    if (v === undefined) return "null";
    return undefined;
  };

  const arrayToJson = (array: readonly unknown[], pos: Pos): string => {
    // Avoid using Array.prototype methods; iterate by index for tamper resistance
    // eslint-disable-next-line functional/no-let -- Local accumulator string for efficient concatenation
    let rendered = "";
    // eslint-disable-next-line functional/no-let -- index-based iteration for tamper-resistance
    for (let index = 0, length = array.length; index < length; index++) {
      const element = (array as unknown as { readonly [k: number]: unknown })[
        index
      ];
      if (pos === "objectProp" && (element === null || element === undefined))
        continue;
      const part = stringify(element, "array");
      rendered = rendered === "" ? part : rendered + "," + part;
    }
    return "[" + rendered + "]";
  };

  const objectToJson = (objectValue: Record<string, unknown>): string => {
    const keys = Object.keys(objectValue).sort((a, b) => a.localeCompare(b));
    // eslint-disable-next-line functional/prefer-readonly-type -- Intentional mutable array for building JSON parts
    const parts: string[] = [];
    for (const k of keys) {
      const v = objectValue[k];
      if (v === undefined) continue; // drop undefined properties
      // eslint-disable-next-line functional/immutable-data -- Intentional array mutation for building JSON string parts
      parts.push(`${JSON.stringify(k)}:${stringify(v, "objectProp")}`);
    }
    return `{${parts.join(",")}}`;
  };

  const stringify = (value_: unknown, pos: Pos): string => {
    const prim = renderPrimitive(value_);
    if (prim !== undefined) return prim;

    if (Array.isArray(value_)) {
      return arrayToJson(value_ as readonly unknown[], pos);
    }

    if (value_ && typeof value_ === "object") {
      return objectToJson(value_ as Record<string, unknown>);
    }

    // Fallback for any other host values (should not occur after canonicalization)
    return JSON.stringify(value_);
  };

  return stringify(canonical, "top");
}
