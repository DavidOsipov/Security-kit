// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Hardened utilities for secure cross-context communication using `postMessage`.
 * - Enforces strict origin validation
 * - Converts incoming payloads to null-prototype objects to prevent prototype pollution
 * - Optional schema or function validators (required in production)
 * - Safe diagnostic/fingerprinting behavior with crypto checks
 *
 * Important runtime behavior changes (compared to earlier draft):
 * - No top-level `await`. Use synchronous environment checks at creation time.
 * - Production requires crypto availability for diagnostics; creation will fail fast
 *   if `crypto.getRandomValues` is not present.
 * - `expectedSource` may be a comparator function for robust cross-context matching.
 *
 * This file contains a few carefully-scoped `eslint-disable` comments to allow
 * low-level, audited mutations (null-proto creation, controlled caches).
 */

/* eslint-disable functional/no-let, functional/immutable-data */

import {
  InvalidParameterError,
  InvalidConfigurationError,
  CryptoUnavailableError,
  TransferableNotAllowedError,
  EncodingError,
  sanitizeErrorForLogs,
} from "./errors.ts";
import { ensureCrypto } from "./state.ts";
import { secureDevLog as secureDevelopmentLog } from "./utils.ts";
import { arrayBufferToBase64 } from "./encoding-utils.ts";
import { SHARED_ENCODER } from "./encoding.ts";
import { isForbiddenKey } from "./constants.ts";
import { environment } from "./environment.ts";
import { normalizeOrigin as normalizeUrlOrigin } from "./url.ts";
import {
  getPostMessageConfig as _getPostMessageConfig,
  MAX_MESSAGE_EVENT_DATA_LENGTH,
} from "./config.ts";

// Re-export a small accessor so consumers/tests that import postMessage
// can read runtime postMessage configuration without importing config.ts
// directly. This preserves backward-compatible test usage like
// `const pm = await import("../../src/postMessage.ts"); pm.getPostMessageConfig()`.
export function getPostMessageConfig() {
  return _getPostMessageConfig();
}

// Allow referencing a build-time macro safely even when not defined in some transforms
// (e.g., manual transpile in VM tests). Using typeof guards avoids ReferenceError at runtime.

declare const __TEST__: boolean | undefined;

// Internal helpers for controlled mutable operations on otherwise readonly types
// Remove readonly from all properties in T
// eslint-disable-next-line functional/prefer-readonly-type -- Intentional mapped type to create a mutable view for controlled internal state
type Mutable<T> = { -readonly [P in keyof T]: T[P] };
type TraversalCounters = {
  readonly nodes: number;
  readonly transferables: number;
};
type TraversalNodes = { readonly nodes: number };

// --- Interfaces and Types ---

export interface SecurePostMessageOptions {
  readonly targetWindow: Window;
  readonly payload: unknown;
  readonly targetOrigin: string;
  readonly wireFormat?: "json" | "structured" | "auto";
  readonly sanitize?: boolean; // default true
  readonly allowTransferables?: boolean; // default false
  readonly allowTypedArrays?: boolean; // default false
}

export interface SecurePostMessageListener {
  readonly destroy: () => void;
}

export type SchemaValue = "string" | "number" | "boolean" | "object" | "array";

export type MessageListenerContext = {
  readonly origin: string;
  readonly source?: unknown;
  readonly ports?: readonly MessagePort[] | undefined;
  readonly event?: MessageEvent;
};

export type CreateSecurePostMessageListenerOptions = {
  readonly allowedOrigins: readonly string[];
  readonly onMessage: (
    data: unknown,
    context?: MessageListenerContext,
  ) => void | Promise<void>; // Handler is not awaited; errors/rejections are captured
  readonly validate?: ((d: unknown) => boolean) | Record<string, SchemaValue>;
  // New hardening options
  readonly allowOpaqueOrigin?: boolean; // default false
  readonly expectedSource?: Window | MessagePort | ((s: unknown) => boolean); // optional stronger binding, now accepts comparator
  readonly allowExtraProps?: boolean; // default false when using schema
  readonly enableDiagnostics?: boolean; // default false; gates fingerprints in prod
  // freezePayload: when true (default), the sanitized payload will be deeply frozen
  // before being passed to the consumer. When false, callers accept responsibility
  // for not mutating the payload.
  readonly freezePayload?: boolean;
  readonly wireFormat?: "json" | "structured" | "auto"; // default json
  readonly deepFreezeNodeBudget?: number;
  readonly allowTransferables?: boolean; // default false: disallow transferables like MessagePort/ArrayBuffer
  readonly allowTypedArrays?: boolean; // default false: disallow TypedArray/DataView/ArrayBuffer without opt-in
};
export { validateTransferables };

// --- Constants ---

// Legacy POSTMESSAGE_MAX_* constants removed. Use getPostMessageConfig() for
// all runtime decisions; callers must not rely on static numeric exports.

// Small default limits for diagnostics to prevent DoS via expensive hashing
const DEFAULT_DIAGNOSTIC_BUDGET = 5; // fingerprints per minute

// Budget for deep-freeze traversal to avoid CPU/DoS via very wide objects
const DEFAULT_DEEP_FREEZE_NODE_BUDGET = 5000; // tunable

function _pmCfg() {
  // Helper to avoid repeated getter import noise and ease auditing
  return getPostMessageConfig();
}

// --- Utilities ---

/**
 * Safe "now" helper that works in browser & node-like hosts.
 */
function now(): number {
  return typeof performance !== "undefined" &&
    typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

/**
 * Synchronous check for presence of a secure RNG in the environment.
 * This intentionally does not await `ensureCrypto()` because some environments
 * require an async initialization; we need a fast, non-async gate for
 * production fail-fast behavior.
 */
function syncCryptoAvailable(): boolean {
  try {
    // globalThis.crypto.getRandomValues presence is the minimal sync capability.
    // In Node 20+, globalThis.crypto is present. In browsers, it is present.
    // This is a conservative check; ensureCrypto() may still be used for
    // full async work (e.g., subtle).
    const g = globalThis as unknown as { readonly crypto?: unknown };
    if (typeof g.crypto === "undefined") return false;
    const c = g.crypto as unknown as { readonly getRandomValues?: unknown };
    return typeof c.getRandomValues === "function";
  } catch {
    return false;
  }
}

// Centralized crypto availability checker with consistent error handling and logging
function checkCryptoAvailabilityForSecurityFeature(
  featureName: string,
  requireInProduction = true,
): void {
  if (!syncCryptoAvailable()) {
    if (requireInProduction && environment.isProduction) {
      // Production requires crypto for security guarantees
      try {
        _diagnosticsDisabledDueToNoCryptoInProduction = true;
        secureDevelopmentLog(
          "error",
          "postMessage",
          `Secure crypto unavailable in production for ${featureName}`,
          {},
        );
      } catch {
        /* best-effort logging */
      }
      throw new CryptoUnavailableError(
        `Secure crypto required in production for ${featureName}`,
      );
    } else if (environment.isProduction) {
      // Non-critical crypto usage in production - disable diagnostics
      try {
        _diagnosticsDisabledDueToNoCryptoInProduction = true;
        secureDevelopmentLog(
          "warn",
          "postMessage",
          `Secure crypto unavailable in production; ${featureName} disabled`,
          {},
        );
      } catch {
        /* best-effort logging */
      }
    }
  }
}

// Helper: call consumer and centralize async rejection/sync throw handling so
// the main `handler` function stays small and easier to lint/verify.
function invokeConsumerSafely(
  consumer: (d: unknown, c?: MessageListenerContext) => void | Promise<void>,
  data: unknown,
  contextOrOrigin: string | MessageListenerContext,
): void {
  // Normalize origin for logging regardless of whether a raw origin string
  // or the richer MessageListenerContext was provided.
  const originForLogs =
    typeof contextOrOrigin === "string"
      ? contextOrOrigin
      : contextOrOrigin.origin;

  try {
    const result = consumer(
      data,
      typeof contextOrOrigin === "string" ? undefined : contextOrOrigin,
    );
    Promise.resolve(result).catch((asyncError: unknown) => {
      try {
        secureDevelopmentLog("error", "postMessage", "Listener handler error", {
          origin: originForLogs,
          error: sanitizeErrorForLogs(asyncError),
        });
      } catch {
        /* best-effort logging */
      }
    });
  } catch (error: unknown) {
    try {
      secureDevelopmentLog("error", "postMessage", "Listener handler error", {
        origin: originForLogs,
        error: sanitizeErrorForLogs(error),
      });
    } catch {
      /* best-effort logging */
    }
  }
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error && typeof error.message === "string"
    ? error.message
    : String(error);
}

function isArrayBufferViewSafe(value: unknown): value is ArrayBufferView {
  try {
    return (
      typeof ArrayBuffer !== "undefined" &&
      typeof ArrayBuffer.isView === "function" &&
      ArrayBuffer.isView(value as ArrayBufferView)
    );
  } catch {
    return false;
  }
}

/**
 * Safely gets the constructor name of an object, handling cross-realm scenarios.
 * @param value The value to get the constructor name for.
 * @returns The constructor name as a string, or undefined if it cannot be determined.
 */
function safeCtorName(value: unknown): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  try {
    // Object.getPrototypeOf returns `any` in lib typings; assert a safe union to avoid unsafe-any
    const proto: object | null = Object.getPrototypeOf(value) as object | null;
    if (!proto || (typeof proto !== "object" && typeof proto !== "function"))
      return undefined;
    // Guarded access to constructor
    const hasCtor = (proto as { readonly constructor?: unknown }).constructor;
    if (typeof hasCtor !== "function") return undefined;
    const nameValue = (hasCtor as { readonly name?: unknown }).name;
    return typeof nameValue === "string" ? nameValue : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Collect own data property descriptors for both string and symbol keys without invoking getters.
 * Skips accessor properties and returns a flat array of [key, value] pairs.
 */
function getOwnDataPropertyEntries(
  object: unknown,
): ReadonlyArray<readonly [string | symbol, unknown]> {
  if (object === null || typeof object !== "object") return [] as const;
  try {
    const names = Object.getOwnPropertyNames(object) as readonly string[];
    const symbols = Object.getOwnPropertySymbols(object) as readonly symbol[];
    // Local accumulator; cast to readonly on return
    // eslint-disable-next-line functional/prefer-readonly-type
    const entries: Array<readonly [string | symbol, unknown]> = [];
    for (const key of names) {
      try {
        const desc = Object.getOwnPropertyDescriptor(
          object as Record<string, unknown>,
          key,
        );
        if (
          !desc ||
          typeof desc.get === "function" ||
          typeof desc.set === "function" ||
          !Object.hasOwn(desc, "value")
        )
          continue;
        entries.push([key, desc.value as unknown]);
      } catch {
        /* ignore faulty descriptor */
      }
    }
    for (const sym of symbols) {
      try {
        const desc = Object.getOwnPropertyDescriptor(object, sym);
        if (
          !desc ||
          typeof desc.get === "function" ||
          typeof desc.set === "function" ||
          !Object.hasOwn(desc, "value")
        )
          continue;
        entries.push([sym, desc.value as unknown]);
      } catch {
        /* ignore faulty descriptor */
      }
    }
    return entries as ReadonlyArray<readonly [string | symbol, unknown]>;
  } catch {
    return [] as const;
  }
}

// --- Internal Security Helpers ---

/**
 * Validates that payload does not contain disallowed transferable objects
 * like MessagePort, ArrayBuffer, or SharedArrayBuffer unless explicitly allowed.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Audited: validates nested structured-clone payloads for transferables; decomposition would harm clarity. Covered by unit/adversarial tests.
function validateTransferables(
  payload: unknown,
  allowTransferables: boolean,
  allowTypedArrays: boolean,
  depth = 0,
  // Use runtime config-driven depth limit; fall back to legacy constant if config missing
  maxDepth = getPostMessageConfig().maxPayloadDepth,
  visited?: WeakSet<object>,
  state?: TraversalCounters,
): void {
  if (depth > maxDepth) return; // depth check handled elsewhere
  if (payload === null || typeof payload !== "object") return;

  // Handle circular references
  visited ??= new WeakSet<object>();
  if (visited.has(payload)) return;

  visited.add(payload);

  // Enforce global traversal/node budget to prevent CPU exhaustion
  // Track a simple node count; if exceeded, fail closed.
  state ??= { nodes: 0, transferables: 0 } as TraversalCounters;
  const mut = state as Mutable<TraversalCounters>;
  mut.nodes += 1;
  const nodeBudget = _pmCfg().maxTraversalNodes;
  if (state.nodes > nodeBudget) {
    throw new InvalidParameterError(
      `Payload traversal exceeds node budget of ${String(nodeBudget)}.`,
    );
  }
  // Helper to count a transferable and enforce cap
  const countTransferable = () => {
    const maxT = _pmCfg().maxTransferables;
    mut.transferables += 1;
    if (state.transferables > maxT) {
      throw new TransferableNotAllowedError(
        `Too many transferable objects in payload (max ${String(maxT)}).`,
      );
    }
  };

  // Check for disallowed transferable types
  const ctorName = safeCtorName(payload);

  // MessagePort and other transferable objects
  if (
    ctorName === "MessagePort" ||
    ctorName === "ReadableStream" ||
    ctorName === "WritableStream" ||
    ctorName === "TransformStream"
  ) {
    if (!allowTransferables) {
      throw new TransferableNotAllowedError(
        `Transferable object ${ctorName} is not allowed unless allowTransferables=true`,
      );
    }
    // Enforce maxTransferables cap when transferables are allowed
    countTransferable();
    return; // do not traverse into host objects
  }

  // ArrayBuffer and typed arrays
  if (ctorName === "ArrayBuffer" || ctorName === "SharedArrayBuffer") {
    if (!allowTypedArrays) {
      throw new TransferableNotAllowedError(
        `${ctorName} is not allowed unless allowTypedArrays=true`,
      );
    }
    // Count as a transferable when allowed and do not traverse further
    // At this point allowTypedArrays is guaranteed true; always count
    countTransferable();
    return;
  }

  // TypedArray and DataView check
  try {
    if (isArrayBufferViewSafe(payload)) {
      if (!allowTypedArrays) {
        throw new TransferableNotAllowedError(
          "TypedArray/DataView is not allowed unless allowTypedArrays=true",
        );
      }
      // allowTypedArrays is guaranteed true here; always count
      countTransferable();
      return; // do not traverse properties of typed arrays/views
    }
  } catch {
    // If ArrayBuffer.isView throws, continue
  }

  // Recursively check nested objects and arrays
  if (Array.isArray(payload)) {
    // Validate array items
    const maxItems = _pmCfg().maxArrayItems;
    if (payload.length > maxItems) {
      throw new InvalidParameterError(
        `Array has too many items (max ${String(maxItems)}).`,
      );
    }
    for (const item of payload) {
      validateTransferables(
        item,
        allowTransferables,
        allowTypedArrays,
        depth + 1,
        maxDepth,
        visited,
        state,
      );
    }
    // Also validate any additional own non-index properties on the array object itself
    const includeSymbols = _pmCfg().includeSymbolKeysInSanitizer;
    const extraProperties = getOwnDataPropertyEntries(payload).filter(
      ([k]) =>
        (typeof k === "string" && k !== "length" && String(Number(k)) !== k) ||
        (typeof k === "symbol" && includeSymbols),
    );
    const maxProperties = _pmCfg().maxObjectKeys;
    const symbolAllowance = includeSymbols ? _pmCfg().maxSymbolKeys : 0;
    if (extraProperties.length > maxProperties + symbolAllowance) {
      throw new InvalidParameterError(
        `Array object has too many own properties (max ${String(maxProperties)}).`,
      );
    }
    for (const [, v] of extraProperties) {
      validateTransferables(
        v,
        allowTransferables,
        allowTypedArrays,
        depth + 1,
        maxDepth,
        visited,
        state,
      );
    }
    return;
  }

  // Validate all own data properties (including non-enumerable and symbols) without invoking getters
  const includeSymbols = _pmCfg().includeSymbolKeysInSanitizer;
  const properties = getOwnDataPropertyEntries(payload).filter(([k]) =>
    typeof k === "symbol" ? includeSymbols : true,
  );
  const maxKeys =
    _pmCfg().maxObjectKeys + (includeSymbols ? _pmCfg().maxSymbolKeys : 0);
  if (properties.length > maxKeys) {
    throw new InvalidParameterError(
      `Object has too many properties (max ${String(maxKeys)}).`,
    );
  }
  for (const [, v] of properties) {
    validateTransferables(
      v,
      allowTransferables,
      allowTypedArrays,
      depth + 1,
      maxDepth,
      visited,
      state,
    );
  }
}

/**
 * Converts objects to null-prototype objects to prevent prototype pollution attacks.
 * Also enforces depth limits and strips forbidden keys.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Audited: prototype-pollution hardening with descriptor guards; splitting risks inconsistencies. Thoroughly tested.
function toNullProto(
  object: unknown,
  depth = 0,
  // Use runtime-configured depth (defense in depth). Accept override via param.
  maxDepth = getPostMessageConfig().maxPayloadDepth,
  visited?: WeakSet<object>,
  nodesLeft?: number,
  state?: TraversalNodes,
): unknown {
  if (depth > maxDepth) {
    throw new InvalidParameterError(
      `Payload depth exceeds limit of ${String(maxDepth)}`,
    );
  }

  if (object === null || typeof object !== "object") {
    return object;
  }

  // Host-type rejection: typed arrays and other exotic host objects should be rejected.
  try {
    // ArrayBuffer view check covers TypedArray and DataView
    if (isArrayBufferViewSafe(object)) {
      throw new InvalidParameterError(
        "Unsupported typed-array or DataView in payload.",
      );
    }
  } catch {
    // If ArrayBuffer.isView throws (very exotic hosts), fall through to other checks
  }

  const ctorName = safeCtorName(object);
  if (
    ctorName === "Map" ||
    ctorName === "Set" ||
    ctorName === "Date" ||
    ctorName === "RegExp" ||
    ctorName === "ArrayBuffer" ||
    ctorName === "DataView" ||
    ctorName === "SharedArrayBuffer" ||
    ctorName === "WeakMap" ||
    ctorName === "WeakSet" ||
    ctorName === "Blob" ||
    ctorName === "File" ||
    ctorName === "URL"
  ) {
    throw new InvalidParameterError(
      // ctorName is narrowed to a string within this branch
      `Unsupported object type in payload: ${ctorName}`,
    );
  }

  // Use a WeakSet per top-level invocation to detect cycles.
  visited ??= new WeakSet<object>();
  // Initialize and enforce a global traversal node budget shared across recursion
  const cfg = _pmCfg();
  state ??= { nodes: nodesLeft ?? cfg.maxTraversalNodes } as TraversalNodes;
  const mut = state as Mutable<TraversalNodes>;
  mut.nodes -= 1;
  if (state.nodes < 0) {
    throw new InvalidParameterError(
      `Payload traversal exceeds node budget of ${String(cfg.maxTraversalNodes)}.`,
    );
  }
  if (visited.has(object)) {
    throw new InvalidParameterError("Circular reference detected in payload.");
  }
  visited.add(object);

  if (Array.isArray(object)) {
    const maxItems = cfg.maxArrayItems;
    const array = object as readonly unknown[];
    if (array.length > maxItems) {
      throw new InvalidParameterError(
        `Array has too many items (max ${String(maxItems)}).`,
      );
    }
    // Map children using the same visited set so cycles across array/object are detected.
    const mapped = array.map((item) =>
      toNullProto(item, depth + 1, maxDepth, visited, undefined, state),
    );
    return mapped;
  }

  // Object.create(null) returns any; cast is safe for fresh object literal use here.

  const out: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  // Iterate over both string and symbol own data properties while avoiding accessors
  const stringKeysAll = Object.getOwnPropertyNames(object);
  const symbolKeysAll = Object.getOwnPropertySymbols(
    object,
  ) as readonly symbol[];
  const maxStringKeys = cfg.maxObjectKeys;
  const maxSymbolKeys = cfg.maxSymbolKeys;
  if (stringKeysAll.length > maxStringKeys) {
    throw new InvalidParameterError(
      `Object has too many string-keyed properties (max ${String(maxStringKeys)}).`,
    );
  }
  const includeSymbols = cfg.includeSymbolKeysInSanitizer;
  if (includeSymbols && symbolKeysAll.length > maxSymbolKeys) {
    throw new InvalidParameterError(
      `Object has too many symbol-keyed properties (max ${String(maxSymbolKeys)}).`,
    );
  }
  const stringKeys = stringKeysAll;
  const symbolKeys = includeSymbols ? symbolKeysAll : ([] as readonly symbol[]);
  for (const key of stringKeys) {
    // Use safe property access to avoid invoking getters
    let value: unknown;
    try {
      const desc = Object.getOwnPropertyDescriptor(
        object as Record<string, unknown>,
        key,
      );
      if (!desc) continue; // skip non-own or otherwise unavailable descriptors
      // Skip accessors to avoid invoking getters
      if (typeof desc.get === "function" || typeof desc.set === "function")
        continue;
      if (!Object.hasOwn(desc, "value")) continue;
      value = desc.value as unknown;
    } catch (error: unknown) {
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Skipped property due to throwing getter",
          { key, error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* best-effort */
      }
      continue;
    }

    // Skip forbidden keys that could enable prototype pollution
    if (isForbiddenKey(key)) {
      continue;
    }

    // Additional defensive check for prototype-related keys
    if (key === "__proto__" || key === "constructor" || key === "prototype")
      continue;

    out[key] = toNullProto(
      value,
      depth + 1,
      maxDepth,
      visited,
      undefined,
      state,
    );
  }

  // Copy over symbol-keyed data properties as well (defense-in-depth). Accessors are skipped.
  try {
    for (const sym of symbolKeys) {
      try {
        const desc = Object.getOwnPropertyDescriptor(object, sym);
        if (
          !desc ||
          typeof desc.get === "function" ||
          typeof desc.set === "function" ||
          !Object.hasOwn(desc, "value")
        )
          continue;
        (out as unknown as Record<symbol, unknown>)[sym] = toNullProto(
          desc.value as unknown,
          depth + 1,
          maxDepth,
          visited,
          undefined,
          state,
        );
      } catch {
        /* ignore symbol copy errors */
      }
    }
  } catch {
    /* ignore */
  }

  return out;
}

// Helper: detect common localhost hostnames and IPv6 loopback forms.
function isHostnameLocalhost(hostname: string): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase().trim();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") return true;
  if (h.startsWith("127.")) return true; // 127.x.x.x
  if (h.startsWith("::ffff:127.")) return true; // IPv4-mapped IPv6
  return false;
}

// Iterative deep-freeze with node budget to avoid deep recursion and DoS via wide structures.
// eslint-disable-next-line sonarjs/cognitive-complexity -- Audited: iterative deep-freeze with DoS budget and best-effort logging. Refactoring would obscure invariants.
function deepFreeze<T>(
  object: T,
  nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET,
): T {
  if (!(object && typeof object === "object")) return object;

  // Quick guard: attempt to freeze shallowly first (best-effort)
  try {
    Object.freeze(object as unknown as object);
  } catch {
    // ignore errors from freezing exotic host objects
  }

  /* eslint-disable functional/no-let, functional/immutable-data, functional/prefer-readonly-type */
  // Iterative traversal stack (mutable local) — safe because this is internal state
  const stack: unknown[] = [object as unknown];
  const seen = new WeakSet<object>();
  let nodes = 0;

  while (stack.length > 0) {
    if (++nodes > nodeBudget) {
      // Budget exceeded; log and stop traversal to avoid CPU exhaustion
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze budget exceeded",
          { nodeBudget },
        );
      } catch {
        /* best-effort */
      }
      break;
    }

    const current = stack.pop();
    if (!current || typeof current !== "object") continue;
    if (seen.has(current)) continue;
    seen.add(current);

    try {
      try {
        Object.freeze(current);
      } catch {
        // ignore freeze errors
      }
      if (Array.isArray(current)) {
        for (const v of current) {
          if (v && typeof v === "object") stack.push(v);
        }
      } else {
        // Use Object.values to iterate own enumerable values (consistent with toNullProto)
        for (const v of Object.values(current as Record<string, unknown>)) {
          if (v && typeof v === "object") stack.push(v);
        }
      }
    } catch (error: unknown) {
      // Best effort logging
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze encountered error while traversing object",
          { error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* ignore */
      }
    }
  }
  /* eslint-enable functional/no-let, functional/immutable-data */

  return object;
}

// --- Public API ---

/**
 * Validates target origin according to OWASP ASVS L3 requirements.
 * Enforces absolute origin, HTTPS preference, and localhost allowance for dev.
 * Dev allowance includes:
 *  - IPv4 loopback (127.0.0.0/8)
 *  - IPv6 loopback (::1)
 *  - IPv4-mapped IPv6 ::ffff:127.0.0.0/8
 */
function validateTargetOrigin(targetOrigin: string): void {
  try {
    const parsed = new URL(targetOrigin);
    // Enforce that an origin string does not include a path/search/hash
    if (
      (parsed.pathname && parsed.pathname !== "/") ||
      parsed.search ||
      parsed.hash
    ) {
      throw new InvalidParameterError(
        "targetOrigin must be a pure origin (no path, query, or fragment).",
      );
    }
    const isLocalhost = isHostnameLocalhost(parsed.hostname);
    if (parsed.origin === "null") {
      throw new InvalidParameterError("targetOrigin 'null' is not allowed.");
    }
    if (parsed.protocol !== "https:" && !isLocalhost) {
      throw new InvalidParameterError(
        "targetOrigin must use https: (localhost allowed for dev).",
      );
    }
  } catch (error: unknown) {
    // Log sanitized parse error and fail loudly per "Fail Loudly, Fail Safely" policy.
    try {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Invalid targetOrigin provided",
        {
          targetOrigin,
          error: sanitizeErrorForLogs(error),
        },
      );
    } catch {
      // best-effort logging; do not leak raw error details
    }
    throw new InvalidParameterError(
      "targetOrigin must be an absolute origin, e.g. 'https://example.com'.",
    );
  }
}

/**
 * Sends a JSON-formatted message with security validation.
 */
function sendJsonMessage(
  targetWindow: Window,
  payload: unknown,
  targetOrigin: string,
  sanitizeOutgoing: boolean,
): void {
  // Serialize first to validate JSON-serializability and enforce size limits
  /* eslint-disable-next-line functional/no-let -- Local serialization variable; scoped to block */
  let serialized: string;
  try {
    const toSend = sanitizeOutgoing ? toNullProto(payload) : payload;
    serialized = JSON.stringify(toSend);
  } catch {
    // JSON.stringify throws TypeError on circular structures
    throw new InvalidParameterError("Payload must be JSON-serializable.");
  }

  // Enforce max payload bytes before sending
  const bytes = SHARED_ENCODER.encode(serialized);
  if (bytes.length > _pmCfg().maxPayloadBytes) {
    throw new InvalidParameterError(
      `Payload exceeds maximum size of ${String(_pmCfg().maxPayloadBytes)} bytes.`,
    );
  }

  try {
    targetWindow.postMessage(serialized, targetOrigin);
  } catch (error: unknown) {
    if (error instanceof TypeError) {
      throw new InvalidParameterError("Payload must be JSON-serializable.");
    }
    throw error;
  }
}

/**
 * Sends a structured clone message with security validation.
 */

function assertStructuredOptions(
  options: SecurePostMessageOptions,
  sanitizeOutgoing: boolean,
): { allowTransferables: boolean; allowTypedArrays: boolean } {
  const allowTransferables = options.allowTransferables ?? false;
  const allowTypedArrays = options.allowTypedArrays ?? false;
  if (sanitizeOutgoing && allowTypedArrays) {
    throw new InvalidParameterError(
      "Incompatible options: sanitize=true is incompatible with allowTypedArrays=true. " +
        "To send TypedArray/DataView/ArrayBuffer, set sanitize=false and ensure allowTypedArrays=true.",
    );
  }
  return { allowTransferables, allowTypedArrays };
}

// Removed unused isJsonSerializablePrimitive helper (previously used only by a removed projection function)

function estimateStructuredPayloadSizeBytes(
  value: unknown,
  sanitized: boolean,
): number | undefined {
  try {
    if (!sanitized) {
      const approx = estimateApproximateSizeBytesBounded(value);
      return typeof approx === "number" ? approx : undefined;
    }
    const stable = stableStringify(
      value,
      _pmCfg().maxPayloadDepth,
      _pmCfg().maxTraversalNodes,
    );
    if (stable.ok) return SHARED_ENCODER.encode(stable.s).length;
  } catch {
    /* ignore estimation errors */
  }
  return undefined;
}

// Best-effort, bounded approximate size estimator for sanitize=false path.
// - Enforces depth and node budgets
// - Limits breadth for arrays and objects to prevent DoS
// - Skips accessors to avoid invoking getters
// Returns a number on success, or +Infinity to force rejection when limits exceeded.
function estimateApproximateSizeBytesBounded(
  value: unknown,
): number | undefined {
  try {
    const INF = Number.POSITIVE_INFINITY;
    const DEPTH_LIMIT = _pmCfg().maxPayloadDepth;
    const cfg = _pmCfg();
    const NODE_BUDGET = cfg.maxTraversalNodes;
    const MAX_ARRAY_ITEMS = cfg.maxArrayItems;
    const MAX_OBJECT_KEYS = cfg.maxObjectKeys;

    const visit = (
      v: unknown,
      depth: number,
      nodesLeft: number,
      seen: WeakSet<object>,
    ): { readonly bytes: number; readonly nodesLeft: number } => {
      if (nodesLeft <= 0 || depth > DEPTH_LIMIT)
        return { bytes: INF, nodesLeft };
      if (v === null) return { bytes: 8, nodesLeft: nodesLeft - 1 };
      const t = typeof v;
      if (t !== "object") {
        return {
          bytes: t === "string" ? (v as string).length : 8,
          nodesLeft: nodesLeft - 1,
        };
      }
      const object = v as object;
      if (seen.has(object)) return { bytes: INF, nodesLeft };
      seen.add(object);
      // Treat typed arrays and ArrayBuffers as terminal nodes with byteLength
      try {
        if (isArrayBufferViewSafe(v)) {
          const view = v;
          return { bytes: 2 + view.byteLength, nodesLeft: nodesLeft - 1 };
        }
      } catch {
        /* ignore */
      }
      const ctorName = safeCtorName(v);
      if (ctorName === "ArrayBuffer" || ctorName === "SharedArrayBuffer") {
        try {
          const length =
            (v as { readonly byteLength?: number }).byteLength ?? 0;
          return { bytes: 2 + length, nodesLeft: nodesLeft - 1 };
        } catch {
          return { bytes: INF, nodesLeft };
        }
      }
      if (Array.isArray(v)) {
        const array = v as readonly unknown[];
        const lim = Math.min(array.length, MAX_ARRAY_ITEMS);
        const result = array.slice(0, lim).reduce(
          (
            accumulator: { readonly bytes: number; readonly nodesLeft: number },
            item,
          ) => {
            const next = visit(item, depth + 1, accumulator.nodesLeft, seen);
            const sum = accumulator.bytes + next.bytes;
            if (!Number.isFinite(sum))
              return { bytes: INF, nodesLeft: 0 } as const;
            return { bytes: sum, nodesLeft: next.nodesLeft } as const;
          },
          { bytes: 2, nodesLeft: nodesLeft - 1 },
        );
        const extra = array.length > lim ? (array.length - lim) * 2 : 0;
        const total = result.bytes + extra;
        return { bytes: total, nodesLeft: result.nodesLeft };
      }
      // object path: enumerable own data properties only (skip accessors)
      const names = Object.getOwnPropertyNames(
        object as Record<string, unknown>,
      );
      const lim = Math.min(names.length, MAX_OBJECT_KEYS);
      const values = names
        .slice(0, lim)
        .map((k) =>
          Object.getOwnPropertyDescriptor(object as Record<string, unknown>, k),
        )
        .filter(
          (d): d is PropertyDescriptor =>
            !!d &&
            typeof d.get !== "function" &&
            typeof d.set !== "function" &&
            !!d.enumerable &&
            Object.hasOwn(d, "value"),
        )
        .map((d) => d.value as unknown);
      const result = values.reduce(
        (
          accumulator: { readonly bytes: number; readonly nodesLeft: number },
          item,
          index,
        ) => {
          const next = visit(item, depth + 1, accumulator.nodesLeft, seen);
          const keyLength = names[index] ? names[index].length : 0;
          const sum = accumulator.bytes + next.bytes + keyLength;
          if (!Number.isFinite(sum))
            return { bytes: INF, nodesLeft: 0 } as const;
          return { bytes: sum, nodesLeft: next.nodesLeft } as const;
        },
        { bytes: 2, nodesLeft: nodesLeft - 1 },
      );
      return result;
    };

    const initialSeen = new WeakSet<object>();
    const result = visit(value, 0, NODE_BUDGET, initialSeen);
    return result.bytes;
  } catch {
    return undefined;
  }
}

function prepareStructuredPayload(
  raw: unknown,
  sanitizeOutgoing: boolean,
  allowTransferables: boolean,
  allowTypedArrays: boolean,
): unknown {
  // Validate transferables before any processing
  try {
    validateTransferables(raw, allowTransferables, allowTypedArrays);
  } catch (error: unknown) {
    if (error instanceof TransferableNotAllowedError) throw error;
    throw new InvalidParameterError(
      "Payload validation failed: " + safeErrorMessage(error),
    );
  }

  if (!sanitizeOutgoing) return raw;
  try {
    return toNullProto(raw);
  } catch (error: unknown) {
    if (error instanceof TransferableNotAllowedError) throw error;
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new InvalidParameterError(
      "Structured-clone payload contains unsupported host objects or circular references: " +
        errorMessage,
    );
  }
}

function processStructuredPayload(
  targetWindow: Window,
  payload: unknown,
  targetOrigin: string,
  sanitizeOutgoing: boolean,
  allowTransferables: boolean,
  allowTypedArrays: boolean,
): void {
  const prepared = prepareStructuredPayload(
    payload,
    sanitizeOutgoing,
    allowTransferables,
    allowTypedArrays,
  );
  // Enforce size cap.
  // 1) Use estimator with traversal caps. If it returns Infinity or > cap, reject.
  // 2) Regardless of estimator, perform a final strict byte-length check by encoding
  //    a safe representation of `prepared` before posting. This guarantees byte-accurate
  //    enforcement even when sanitize=false. We avoid deep serialization on exotic
  //    types; for typed arrays and buffers, we count their byteLength directly.
  const estimated = estimateStructuredPayloadSizeBytes(
    prepared,
    sanitizeOutgoing,
  );
  if (typeof estimated === "number") {
    if (!Number.isFinite(estimated) || estimated > _pmCfg().maxPayloadBytes) {
      throw new InvalidParameterError(
        `Payload exceeds maximum size of ${String(_pmCfg().maxPayloadBytes)} bytes.`,
      );
    }
  }

  // Strict final byte-accurate check. We attempt to compute a conservative
  // byte length without fully serializing arbitrary objects when sanitize=false.
  // Strategy:
  // - If sanitized or JSON-serializable, use stableStringify for deterministic bytes.
  // - Else, compute an upper bound by walking common containers and summing byte lengths
  //   (typed arrays and buffers by byteLength; strings by UTF-8 length) under traversal caps.
  const strictByteLength = ((): number | undefined => {
    try {
      if (sanitizeOutgoing) {
        const stable = stableStringify(
          prepared,
          _pmCfg().maxPayloadDepth,
          _pmCfg().maxTraversalNodes,
        );
        if (stable.ok) return SHARED_ENCODER.encode(stable.s).length;
      }
    } catch {
      /* fall through to conservative estimator */
    }
    // Fallback: compute conservative upper bound without serialization.
    try {
      const INF = Number.POSITIVE_INFINITY;
      const DEPTH_LIMIT = _pmCfg().maxPayloadDepth;
      const cfg = _pmCfg();
      const NODE_BUDGET = cfg.maxTraversalNodes;
      const MAX_ARRAY_ITEMS = cfg.maxArrayItems;
      const MAX_OBJECT_KEYS = cfg.maxObjectKeys;
      const visit = (
        v: unknown,
        depth: number,
        nodesLeft: number,
        seen: WeakSet<object>,
      ): { readonly bytes: number; readonly nodesLeft: number } => {
        if (nodesLeft <= 0 || depth > DEPTH_LIMIT)
          return { bytes: INF, nodesLeft };
        if (v === null) return { bytes: 4, nodesLeft: nodesLeft - 1 };
        const t = typeof v;
        if (typeof v === "string")
          return {
            bytes: SHARED_ENCODER.encode(v).length,
            nodesLeft: nodesLeft - 1,
          };
        if (t === "number" || t === "boolean")
          return { bytes: 8, nodesLeft: nodesLeft - 1 };
        if (t !== "object") return { bytes: 0, nodesLeft: nodesLeft - 1 };
        const object = v as object;
        if (seen.has(object)) return { bytes: INF, nodesLeft };
        seen.add(object);
        try {
          if (isArrayBufferViewSafe(v)) {
            const view = v;
            return { bytes: view.byteLength, nodesLeft: nodesLeft - 1 };
          }
        } catch {
          /* ignore */
        }
        const ctor = safeCtorName(v);
        if (ctor === "ArrayBuffer" || ctor === "SharedArrayBuffer") {
          try {
            const length =
              (v as { readonly byteLength?: number }).byteLength ?? 0;
            return { bytes: length, nodesLeft: nodesLeft - 1 };
          } catch {
            return { bytes: INF, nodesLeft };
          }
        }
        if (Array.isArray(v)) {
          const array = v as readonly unknown[];
          const lim = Math.min(array.length, MAX_ARRAY_ITEMS);
          const reduction = array.slice(0, lim).reduce(
            (
              accumulator: {
                readonly bytes: number;
                readonly nodesLeft: number;
              },
              item,
            ) => {
              const next = visit(item, depth + 1, accumulator.nodesLeft, seen);
              const sum = accumulator.bytes + next.bytes;
              if (!Number.isFinite(sum))
                return { bytes: INF, nodesLeft: 0 } as const;
              return { bytes: sum, nodesLeft: next.nodesLeft } as const;
            },
            { bytes: 0, nodesLeft: nodesLeft - 1 },
          );
          // Penalize truncated tail minimally
          const extra = array.length > lim ? (array.length - lim) * 1 : 0;
          return {
            bytes: reduction.bytes + extra,
            nodesLeft: reduction.nodesLeft,
          };
        }
        // object: enumerable own data properties only
        const names = Object.getOwnPropertyNames(
          object as Record<string, unknown>,
        );
        const lim = Math.min(names.length, MAX_OBJECT_KEYS);
        const reduction = names.slice(0, lim).reduce(
          (
            accumulator: { readonly bytes: number; readonly nodesLeft: number },
            name,
            _index,
          ) => {
            const desc = Object.getOwnPropertyDescriptor(
              object as Record<string, unknown>,
              name,
            );
            if (
              !desc ||
              typeof desc.get === "function" ||
              typeof desc.set === "function" ||
              !desc.enumerable ||
              !Object.hasOwn(desc, "value")
            )
              return accumulator;
            const keyBytes = SHARED_ENCODER.encode(name).length;
            const next = visit(
              desc.value,
              depth + 1,
              accumulator.nodesLeft,
              seen,
            );
            const sum = accumulator.bytes + keyBytes + next.bytes;
            if (!Number.isFinite(sum))
              return { bytes: INF, nodesLeft: 0 } as const;
            return { bytes: sum, nodesLeft: next.nodesLeft } as const;
          },
          { bytes: 0, nodesLeft: nodesLeft - 1 },
        );
        return { bytes: reduction.bytes, nodesLeft: reduction.nodesLeft };
      };
      const result = visit(prepared, 0, NODE_BUDGET, new WeakSet<object>());
      return result.bytes;
    } catch {
      return undefined;
    }
  })();

  if (
    typeof strictByteLength === "number" &&
    (!Number.isFinite(strictByteLength) ||
      strictByteLength > _pmCfg().maxPayloadBytes)
  ) {
    throw new InvalidParameterError(
      `Payload exceeds maximum size of ${String(_pmCfg().maxPayloadBytes)} bytes.`,
    );
  }
  try {
    targetWindow.postMessage(prepared, targetOrigin);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new InvalidParameterError(
      "Failed to post structured payload: ensure payload is structured-cloneable: " +
        errorMessage,
    );
  }
}

function sendStructuredMessage(
  options: SecurePostMessageOptions,
  targetWindow: Window,
  payload: unknown,
  targetOrigin: string,
  sanitizeOutgoing: boolean,
): void {
  // Structured: allow posting non-string data. 'auto' may be downgraded on receive.
  // By default we sanitize outgoing payloads to null-proto version to avoid prototype pollution.
  const { allowTransferables, allowTypedArrays } = assertStructuredOptions(
    options,
    sanitizeOutgoing,
  );
  processStructuredPayload(
    targetWindow,
    payload,
    targetOrigin,
    sanitizeOutgoing,
    allowTransferables,
    allowTypedArrays,
  );
}

export function sendSecurePostMessage(options: SecurePostMessageOptions): void {
  const { targetWindow, payload, targetOrigin } = options;
  const wireFormat = options.wireFormat ?? "json";
  const sanitizeOutgoing = options.sanitize !== false; // default true
  // Runtime guard for defense-in-depth: ensure a real targetWindow is supplied
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Defense-in-depth: runtime guard even if type says Window
  if (!targetWindow)
    throw new InvalidParameterError("targetWindow must be provided.");
  if (targetOrigin === "*")
    throw new InvalidParameterError("targetOrigin cannot be a wildcard ('*').");
  // Runtime guard for defense-in-depth: validate explicit string targetOrigin
  if (!targetOrigin || typeof targetOrigin !== "string")
    throw new InvalidParameterError("targetOrigin must be a specific string.");

  // Validate target origin with security checks
  validateTargetOrigin(targetOrigin);

  // Handle wire formats using a switch for clarity and lint friendliness
  switch (wireFormat) {
    case "json":
      sendJsonMessage(targetWindow, payload, targetOrigin, sanitizeOutgoing);
      return;
    case "structured":
    case "auto":
      sendStructuredMessage(
        options,
        targetWindow,
        payload,
        targetOrigin,
        sanitizeOutgoing,
      );
      return;
    default:
      throw new InvalidParameterError("Unsupported wireFormat");
  }
}

/*
  The following function coordinates multiple security checks and option normalizations.
  Its control flow is intentionally explicit for auditability (OWASP ASVS L3). Further
  refactoring would increase indirection and risk subtle security regressions. We disable
  the cognitive-complexity rule for this function only, with a clear justification.
*/
/* eslint-disable sonarjs/cognitive-complexity */
export function createSecurePostMessageListener(
  allowedOriginsOrOptions:
    | readonly string[]
    | CreateSecurePostMessageListenerOptions,
  onMessageOptional?: (data: unknown) => void | Promise<void>,
): SecurePostMessageListener {
  /* eslint-disable functional/no-let -- Local parsing variables for parameter overloading; scoped to function */
  let allowedOrigins: readonly string[] | undefined,
    onMessage: (data: unknown) => void | Promise<void>,
    validator:
      | ((d: unknown) => boolean)
      | Record<string, SchemaValue>
      | undefined;

  let optionsObject: CreateSecurePostMessageListenerOptions | undefined;
  /* eslint-enable functional/no-let */

  if (Array.isArray(allowedOriginsOrOptions)) {
    allowedOrigins = allowedOriginsOrOptions;
    if (!onMessageOptional) {
      throw new InvalidParameterError(
        "onMessage callback is required when passing allowed origins array.",
      );
    }
    onMessage = onMessageOptional as (data: unknown) => void;
  } else {
    optionsObject =
      allowedOriginsOrOptions as CreateSecurePostMessageListenerOptions;
    allowedOrigins = optionsObject.allowedOrigins;
    onMessage = optionsObject.onMessage;
    validator = optionsObject.validate;
  }

  // Production-time synchronous crypto availability check:
  checkCryptoAvailabilityForSecurityFeature("postMessage diagnostics", true);

  // In production, require explicit channel binding and a validator to avoid
  // creating a listener that accepts messages from any origin/source.
  const hasAllowedOrigins =
    Array.isArray(allowedOrigins) && allowedOrigins.length > 0;
  const hasExpectedSource =
    typeof optionsObject?.expectedSource !== "undefined";
  if (environment.isProduction && !(hasAllowedOrigins || hasExpectedSource)) {
    throw new InvalidConfigurationError(
      "createSecurePostMessageListener requires 'allowedOrigins' or 'expectedSource' in production.",
    );
  }

  // If production, require validator presence to force positive validation
  if (environment.isProduction && !validator) {
    throw new InvalidConfigurationError(
      "createSecurePostMessageListener requires 'validate' in production.",
    );
  }

  // Lock configuration at creation time to prevent TOCTOU attacks
  // Build canonical options object and freeze it to prevent mutation
  const allowedOriginsNormalized = Array.isArray(allowedOrigins)
    ? allowedOrigins
    : ([] as readonly string[]);
  const finalOptions = (
    optionsObject
      ? { ...optionsObject, allowedOrigins: optionsObject.allowedOrigins }
      : {
          allowedOrigins: allowedOriginsNormalized,
          onMessage,
          validate: validator,
          allowOpaqueOrigin: false,
          expectedSource: undefined,
          allowExtraProps: false,
          enableDiagnostics: false,
          freezePayload: true,
          wireFormat: "json",
          deepFreezeNodeBudget: DEFAULT_DEEP_FREEZE_NODE_BUDGET,
          allowTransferables: false,
          allowTypedArrays: false,
        }
  ) as CreateSecurePostMessageListenerOptions;
  Object.freeze(finalOptions);

  // Extract immutable locals to prevent runtime configuration changes
  const validatorLocal:
    | ((d: unknown) => boolean)
    | Record<string, SchemaValue>
    | undefined = finalOptions.validate;
  const expectedSourceLocal: CreateSecurePostMessageListenerOptions["expectedSource"] =
    finalOptions.expectedSource;
  const allowExtraPropertiesLocal = finalOptions.allowExtraProps ?? false;
  const freezePayloadLocal = finalOptions.freezePayload !== false;
  const enableDiagnosticsLocal = !!finalOptions.enableDiagnostics;
  const wireFormatLocal = finalOptions.wireFormat ?? "json";
  const allowTransferablesLocal = !!finalOptions.allowTransferables;
  const allowTypedArraysLocal = !!finalOptions.allowTypedArrays;
  const allowOpaqueOriginLocal = !!finalOptions.allowOpaqueOrigin;
  /* deepFreezeNodeBudgetLocal intentionally unused here; use finalOptions.deepFreezeNodeBudget where needed */

  // Normalize origins to canonical form to avoid mismatches like :443 vs default
  function normalizeOrigin(o: string): string {
    try {
      // Reuse shared URL normalization
      const norm = normalizeUrlOrigin(o);
      // Validate canonicalization by parsing norm
      const u = new URL(norm);
      if (u.origin === "null") throw new InvalidParameterError("opaque origin");
      const isLocalhost = isHostnameLocalhost(u.hostname);
      if (u.protocol !== "https:" && !isLocalhost)
        throw new InvalidParameterError("insecure origin");
      return norm;
    } catch {
      // Fallback: accept explicit http://localhost(:port) forms that may not
      // pass stricter URL normalization but are valid development origins.
      try {
        const u = new URL(o);
        // Ensure it's a pure origin
        if ((u.pathname && u.pathname !== "/") || u.search || u.hash)
          throw new Error("not-origin");
        const isLocalhost = isHostnameLocalhost(u.hostname);
        if (u.protocol === "http:" && isLocalhost) {
          // Return a canonical origin string
          const portPart = u.port ? `:${u.port}` : "";
          return `${u.protocol}//${u.hostname}${portPart}`;
        }
      } catch {
        /* fall through to error below */
      }

      throw new InvalidParameterError(
        `Invalid allowed origin '${o}'. Use an absolute origin 'https://example.com' or 'http://localhost'.`,
      );
    }
  }

  // Build the canonical allowed origin set and an abort controller for the
  // event listener lifecycle. If any origin is invalid, collect them and
  // throw a single informative error.
  const initialReduction: { allowed: Set<string>; invalid: string[] } = {
    allowed: new Set<string>(),
    invalid: [],
  };
  const originReduction = finalOptions.allowedOrigins.reduce<{
    allowed: Set<string>;
    invalid: string[];
  }>((accumulator, o) => {
    try {
      const n = normalizeOrigin(o);
      return {
        allowed: new Set<string>([...accumulator.allowed, n]),
        invalid: accumulator.invalid,
      };
    } catch {
      return {
        allowed: accumulator.allowed,
        invalid: [...accumulator.invalid, o],
      };
    }
  }, initialReduction);
  const allowedOriginSet = originReduction.allowed;
  const invalidOrigins = originReduction.invalid as readonly string[];
  if (invalidOrigins.length > 0) {
    throw new InvalidParameterError(
      `Invalid allowedOrigins provided: ${invalidOrigins.join(", ")}`,
    );
  }

  const abortController = new AbortController();
  // Diagnostic budget to limit expensive fingerprinting on the failure path
  /* eslint-disable functional/no-let -- Local diagnostic state; scoped to function */
  let diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
  let diagnosticLastRefill = now();
  function canConsumeDiagnostic(): boolean {
    const n = now();
    if (n - diagnosticLastRefill > 60_000) {
      diagnosticBudget = DEFAULT_DIAGNOSTIC_BUDGET;
      diagnosticLastRefill = n;
    }
    if (diagnosticBudget > 0) {
      diagnosticBudget -= 1;
      return true;
    }
    return false;
  }
  /* eslint-enable functional/no-let */

  // Module-scoped cache to avoid re-freezing identical object instances.
  function getDeepFreezeCache(): WeakSet<object> | undefined {
    try {
      // Use an internal well-known symbol to attach a cache to the deepFreeze
      const key = Symbol.for("__security_kit_deep_freeze_cache_v1");
      const holder = deepFreeze as unknown as Record<
        symbol,
        WeakSet<object> | undefined
      >;
      // Use nullish coalescing assignment when possible to avoid repeated lookups
      /* eslint-disable-next-line functional/immutable-data -- Local cache initialization; safe operation */
      holder[key] ??= new WeakSet<object>();
      return holder[key];
    } catch {
      return undefined;
    }
  }

  function freezePayloadIfNeeded(payload: unknown): void {
    if (finalOptions.freezePayload === false) return; // default true: freeze
    if (payload == undefined || typeof payload !== "object") return;
    const asObject = payload;
    const nodeBudget =
      finalOptions.deepFreezeNodeBudget ?? DEFAULT_DEEP_FREEZE_NODE_BUDGET;

    const logDeepFreezeIssue = (error: unknown): void => {
      try {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "deepFreeze failed or budget exceeded while freezing payload",
          { error: sanitizeErrorForLogs(error) },
        );
      } catch {
        /* ignore */
      }
    };

    const cache = getDeepFreezeCache();
    if (cache) {
      if (cache.has(asObject)) return;
      try {
        deepFreeze(asObject, nodeBudget);
      } catch (error: unknown) {
        logDeepFreezeIssue(error);
      }
      try {
        cache.add(asObject);
      } catch {
        /* ignore */
      }
      return;
    }
    try {
      deepFreeze(asObject, nodeBudget);
    } catch (error: unknown) {
      logDeepFreezeIssue(error);
    }
  }

  const handler = (event: MessageEvent) => {
    // Validate origin and source using extracted helpers to reduce cognitive complexity
    if (!isEventOriginAllowlisted(event)) return;
    if (!isEventSourceExpected(event)) return;
    try {
      const data = parseMessageEventData(event);

      if (!validatorLocal) {
        // Defensive: validator should always be present due to creation-time checks
        secureDevelopmentLog(
          "error",
          "postMessage",
          "Message validator missing at runtime",
          {},
        );
        return;
      }

      const validationResult = _validatePayloadWithExtras(
        data,
        validatorLocal,
        allowExtraPropertiesLocal,
      );
      if (!validationResult.valid) {
        // Gate expensive fingerprinting behind diagnostics and a small budget to avoid DoS
        scheduleDiagnosticForFailedValidation(
          event.origin,
          validationResult.reason,
          data,
        );
        return;
      }

      // Freeze payload by default (immutable) with an identity cache to avoid
      // repeated work. Consumers can opt out with freezePayload: false.
      if (freezePayloadLocal) freezePayloadIfNeeded(data);
      // Build a small context object to give consumers access to event-level
      // details such as origin, source and ports. This keeps the onMessage
      // signature backwards-compatible (second param optional).
      const context: MessageListenerContext = {
        origin: event.origin,
        source: event.source,
        ports: event.ports as unknown as readonly MessagePort[] | undefined,
        event,
      };
      // Call the consumer in a small helper so this handler stays simple.
      invokeConsumerSafely(
        onMessage as (d: unknown, c?: unknown) => void | Promise<void>,
        data,
        context,
      );
    } catch (unknownError: unknown) {
      const safeError = sanitizeErrorForLogs(unknownError);
      secureDevelopmentLog("error", "postMessage", "Listener handler error", {
        origin: event.origin,
        error: safeError,
      });
    }
  };

  function isEventOriginAllowlisted(event: MessageEvent): boolean {
    // Treat empty string and 'null' as opaque origin markers. By default we
    // reject opaque origins because they are hard to reason about. If the
    // listener explicitly opted into `allowOpaqueOrigin`, accept them and
    // skip canonical normalization checks.
    const incoming = typeof event.origin === "string" ? event.origin : "";
    const isOpaque = incoming === "" || incoming === "null";
    if (isOpaque) {
      if (!allowOpaqueOriginLocal) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message due to invalid origin format",
          {
            origin: incoming,
          },
        );
        return false;
      }
      // If opaque origins are allowed, skip normalization and allow the message
      // to proceed to other checks (e.g., expectedSource). This keeps the
      // explicit opt-in behavior while allowing reply-port based scenarios.
      return true;
    }

    try {
      if (!allowedOriginSet.has(normalizeOrigin(incoming))) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message from non-allowlisted origin",
          {
            origin: incoming,
          },
        );
        return false;
      }
    } catch (unknownError: unknown) {
      const safeError = sanitizeErrorForLogs(unknownError);
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message due to invalid origin format",
        {
          origin: incoming,
          error: safeError,
        },
      );
      return false;
    }
    return true;
  }

  function isEventSourceExpected(event: MessageEvent): boolean {
    if (typeof expectedSourceLocal === "undefined") return true;
    const expected = expectedSourceLocal;
    // If expectedSource is a comparator function, call it
    if (typeof expected === "function") {
      try {
        const ok = (expected as (s: unknown) => boolean)(event.source);
        if (!ok) {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Dropped message from unexpected source (comparator mismatch)",
            {
              origin: event.origin,
            },
          );
        }
        return ok;
      } catch (error: unknown) {
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Dropped message due to expectedSource comparator throwing",
          {
            origin: event.origin,
            error: sanitizeErrorForLogs(error),
          },
        );
        return false;
      }
    }
    // Otherwise do strict reference equality
    // Equal by identity; cast to unknown to avoid cross-realm type noise
    if (
      typeof expected !== "undefined" &&
      (event.source as unknown) !== (expected as unknown)
    ) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Dropped message from unexpected source (reference mismatch)",
        {
          origin: event.origin,
        },
      );
      return false;
    }
    return true;
  }

  // Schedule diagnostics for failed validation: use the diagnostic budget and
  // a salted fingerprint when available. This is extracted to keep handler
  // cognitive complexity under limits.
  function scheduleDiagnosticForFailedValidation(
    origin: string,
    reason: string | undefined,
    data: unknown,
  ): void {
    const enableDiagnostics = enableDiagnosticsLocal;
    if (
      !enableDiagnostics ||
      !canConsumeDiagnostic() ||
      _diagnosticsDisabledDueToNoCryptoInProduction
    ) {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Message dropped due to failed validation",
        {
          origin,
          reason,
        },
      );
      return;
    }

    // Async helper: attempt to compute fingerprint and log it.
    const computeAndLog = async () => {
      try {
        await ensureCrypto();
      } catch {
        // No secure crypto available: respect production policy and avoid
        // creating low-entropy fingerprints. If in production, disable
        // future diagnostics that would rely on non-crypto fallbacks.
        try {
          if (environment.isProduction)
            _diagnosticsDisabledDueToNoCryptoInProduction = true;
        } catch {
          /* ignore */
        }
        secureDevelopmentLog(
          "warn",
          "postMessage",
          "Message dropped due to failed validation",
          { origin, reason },
        );
        return;
      }

      // Attempt fingerprinting and log result (async). Errors handled per-case.
      getPayloadFingerprint(data)
        .then((fp) => {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            { origin, reason, fingerprint: fp },
          );
        })
        .catch(() => {
          secureDevelopmentLog(
            "warn",
            "postMessage",
            "Message dropped due to failed validation",
            { origin, reason },
          );
        });
    };

    // Fire-and-forget the async helper; errors are handled internally.
    void computeAndLog();
  }

  function parseMessageEventData(event: MessageEvent): unknown {
    const wireFormat = wireFormatLocal;
    if (
      typeof event.data === "string" &&
      event.data.length > MAX_MESSAGE_EVENT_DATA_LENGTH
    ) {
      throw new InvalidParameterError(
        `postMessage payload exceeds maximum length (${String(MAX_MESSAGE_EVENT_DATA_LENGTH)}).`,
      );
    }

    // If structured/auto, allow non-string data when appropriate
    if (wireFormat === "structured") {
      // Accept structured clone payloads but sanitize and enforce host-type disallow rules
      if (event.data === null || typeof event.data !== "object") {
        // primitive types are acceptable via structured clone
        return event.data;
      }
      // Use locked configuration values from creation time

      // Use strict transferable validation
      try {
        validateTransferables(
          event.data,
          allowTransferablesLocal,
          allowTypedArraysLocal,
          0,
          getPostMessageConfig().maxPayloadDepth,
          undefined,
          { nodes: 0, transferables: 0 },
        );
      } catch (error: unknown) {
        if (error instanceof TransferableNotAllowedError) {
          throw error; // Re-throw specific transferable errors
        }
        throw new InvalidParameterError(
          "Received payload validation failed: " +
            (error instanceof Error && typeof error.message === "string"
              ? error.message
              : String(error)),
        );
      }

      // Special handling for ArrayBuffers when allowed
      if (allowTypedArraysLocal && event.data instanceof ArrayBuffer) {
        return event.data; // Return ArrayBuffer as-is without toNullProto processing
      }

      // Convert to null-prototype and enforce depth/forbidden keys
      return toNullProto(event.data, 0, getPostMessageConfig().maxPayloadDepth);
    }

    if (wireFormat === "auto") {
      // auto: accept structured clone only for same-origin messages; otherwise require JSON string
      try {
        const sameOrigin =
          normalizeUrlOrigin(event.origin) ===
          normalizeUrlOrigin(location.origin);
        if (
          sameOrigin &&
          event.data !== null &&
          typeof event.data === "object"
        ) {
          return toNullProto(
            event.data,
            0,
            getPostMessageConfig().maxPayloadDepth,
          );
        }
      } catch {
        // fall back to JSON handling below
      }
      // else treat as JSON string path
    }

    // Default JSON path: require string
    if (typeof event.data !== "string") {
      // Reject non-string payloads to avoid structured clone cycles and ambiguous typing
      throw new InvalidParameterError(
        "postMessage payload must be a JSON string",
      );
    }
    if (event.data.length > MAX_MESSAGE_EVENT_DATA_LENGTH) {
      throw new InvalidParameterError(
        `JSON payload exceeds maximum length (${String(MAX_MESSAGE_EVENT_DATA_LENGTH)}).`,
      );
    }
    const byteLength = SHARED_ENCODER.encode(event.data).length;
    // Enforce stricter textual JSON input guard (centralized constant) prior to parse
    if (byteLength > getPostMessageConfig().maxJsonTextBytes) {
      throw new InvalidParameterError(
        `JSON payload exceeds textual byte limit (${String(getPostMessageConfig().maxJsonTextBytes)}).`,
      );
    }
    if (byteLength > _pmCfg().maxPayloadBytes) {
      secureDevelopmentLog("warn", "postMessage", "Dropped oversized payload", {
        origin: event.origin,
      });
      throw new InvalidParameterError("Payload exceeds maximum allowed size.");
    }
    // eslint-disable-next-line functional/no-let -- Local parsed variable; scoped to function
    let parsed: unknown;
    try {
      parsed = JSON.parse(event.data);
    } catch {
      throw new InvalidParameterError("Invalid JSON in postMessage");
    }
    // Convert to null-prototype objects and enforce depth + forbidden keys
    return toNullProto(parsed, 0, getPostMessageConfig().maxPayloadDepth);
  }

  // Use globalThis.addEventListener so the listener works both on the main
  // thread (window) and in worker contexts (self/globalThis). Cast to any to
  // avoid TypeScript errors in non-DOM environments.
  // Prefer `window.addEventListener` when available (tests often stub `window`).
  const globalTarget: { addEventListener?: unknown } =
    typeof window !== "undefined" &&
    (window as unknown as { addEventListener?: unknown }).addEventListener
      ? (window as unknown as { addEventListener?: unknown })
      : (globalThis as unknown as { addEventListener?: unknown });
  try {
    (
      globalTarget as unknown as {
        addEventListener: (
          type: string,
          listener: EventListenerOrEventListenerObject,
          options?: AddEventListenerOptions,
        ) => void;
      }
    ).addEventListener(
      "message",
      handler as EventListenerOrEventListenerObject,
      { signal: abortController.signal } as AddEventListenerOptions,
    );
  } catch (error) {
    // If addEventListener is not available on the selected target, surface a clear error.
    // OWASP ASVS L3: Log the error for debugging but don't expose sensitive details
    try {
      secureDevelopmentLog("error", "postMessage", "addEventListener failed", {
        error: sanitizeErrorForLogs(error),
      });
    } catch {
      /* best-effort logging */
    }
    throw new InvalidConfigurationError(
      "Global event target does not support addEventListener",
    );
  }
  return {
    destroy: () => {
      abortController.abort();
    },
  };
}
/* eslint-enable sonarjs/cognitive-complexity */

// --- Internal Helpers ---

// Deterministic, stable JSON serialization used for fingerprinting only.
// The normalization routine is small but involves a couple of branches that trip cognitive-complexity.
// We keep it together for auditability and determinism; splitting harms the guarantee.
function stableStringify(
  object: unknown,
  maxDepth = getPostMessageConfig().maxPayloadDepth,
  nodeBudget = DEFAULT_DEEP_FREEZE_NODE_BUDGET,
):
  | { readonly ok: true; readonly s: string }
  | { readonly ok: false; readonly reason: string } {
  /* eslint-disable functional/no-let -- Local serialization state; scoped to function */
  const seen = new WeakSet<object>();
  let nodes = 0;

  function norm(o: unknown, depth: number): unknown {
    if (++nodes > nodeBudget) throw new InvalidParameterError("budget");
    if (o === null || typeof o !== "object") return o;
    if (depth > maxDepth) throw new InvalidParameterError("depth");
    if (seen.has(o)) throw new InvalidParameterError("circular");
    seen.add(o);
    if (Array.isArray(o))
      return (o as readonly unknown[]).map((v) => norm(v, depth + 1));
    const keys = Object.keys(o as Record<string, unknown>).sort((a, b) =>
      a.localeCompare(b),
    );
    /* eslint-disable functional/immutable-data -- Building new null-proto object; local writes to fresh object are safe */
    const result = Object.create(null) as Record<string, unknown>;
    for (const k of keys) {
      result[k] = norm((o as Record<string, unknown>)[k], depth + 1);
    }
    /* eslint-enable functional/immutable-data */
    return result;
  }

  try {
    const normalized = norm(object, 0);
    return { ok: true, s: JSON.stringify(normalized) };
  } catch (error: unknown) {
    return {
      ok: false,
      reason:
        error instanceof Error && typeof error.message === "string"
          ? error.message
          : "error",
    };
  }
  /* eslint-enable functional/no-let */
}

// Memoized salt initialization promise to avoid races when multiple callers
// request a salt concurrently.
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for salt memoization; audited */
let _payloadFingerprintSaltPromise: Promise<Uint8Array> | undefined;

// Salt used to make fingerprints non-linkable across process restarts.
// Generated lazily using secure RNG when available.
const FINGERPRINT_SALT_LENGTH = 16;
// Use `undefined` as the uninitialised sentinel to align with lint rules
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for salt memoization; audited */
let _payloadFingerprintSalt: Uint8Array | undefined;
// If secure crypto is not available in production, disable diagnostics that
// rely on non-crypto fallbacks.
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for diagnostics flag; audited */
let _diagnosticsDisabledDueToNoCryptoInProduction = false;

// Cooldown period in milliseconds to prevent thundering herd on repeated failures
// when generating the fingerprint salt. This avoids repeated rapid retries
// hitting the underlying crypto initialization when it's failing transiently.
const SALT_FAILURE_COOLDOWN_MS = 5_000;
/* eslint-disable-next-line functional/no-let -- Controlled, file-local state for failure backoff; audited */
let _saltGenerationFailureTimestamp: number | undefined;

async function ensureFingerprintSalt(): Promise<Uint8Array> {
  if (_payloadFingerprintSalt !== undefined) return _payloadFingerprintSalt;

  // If a generation promise is already in-flight, reuse it to avoid races.
  if (_payloadFingerprintSaltPromise !== undefined)
    return _payloadFingerprintSaltPromise;

  // If we recently observed a failure to generate a salt, fail-fast for a
  // short cooldown period to avoid thundering-herd retries against a failing
  // underlying initialization (e.g., ensureCrypto()).
  if (
    typeof _saltGenerationFailureTimestamp !== "undefined" &&
    now() - _saltGenerationFailureTimestamp < SALT_FAILURE_COOLDOWN_MS
  ) {
    throw new CryptoUnavailableError(
      "Salt generation failed recently; on cooldown.",
    );
  }
  // Fast synchronous availability check: if in production and crypto is missing,
  // we fail fast rather than relying on time-based fallback.
  checkCryptoAvailabilityForSecurityFeature(
    "fingerprint salt generation",
    true,
  );

  const disableDiagnosticsInProduction = (error: unknown): never => {
    try {
      _diagnosticsDisabledDueToNoCryptoInProduction = true;
    } catch {
      /* ignore */
    }
    try {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Secure crypto unavailable in production; disabling diagnostics that rely on non-crypto fallbacks",
        { error: sanitizeErrorForLogs(error) },
      );
    } catch {
      /* ignore */
    }
    throw new CryptoUnavailableError();
  };

  const generateDevelopmentSalt = (error: unknown): Uint8Array => {
    try {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Falling back to non-crypto fingerprint salt (dev/test only)",
        { error: sanitizeErrorForLogs(error) },
      );
    } catch {
      /* ignore */
    }
    const timeEntropy =
      String(Date.now()) +
      String(
        typeof performance !== "undefined" &&
          typeof performance.now === "function"
          ? performance.now()
          : 0,
      );
    const buf = new Uint8Array(FINGERPRINT_SALT_LENGTH);
    /* eslint-disable functional/no-let, functional/immutable-data -- Local loop index and buffer initialization; scoped */
    for (let index = 0; index < buf.length; index++) {
      buf[index] = timeEntropy.charCodeAt(index % timeEntropy.length) & 0xff;
    }
    /* eslint-enable functional/no-let, functional/immutable-data */
    return buf;
  };

  const generateSalt = async (): Promise<Uint8Array> => {
    try {
      const crypto = await ensureCrypto();
      const salt = new Uint8Array(FINGERPRINT_SALT_LENGTH);
      crypto.getRandomValues(salt);
      return salt;
    } catch (error: unknown) {
      _saltGenerationFailureTimestamp = now();
      if (environment.isProduction)
        return disableDiagnosticsInProduction(error);
      return generateDevelopmentSalt(error);
    }
  };

  _payloadFingerprintSaltPromise = (async () => {
    const salt = await generateSalt();
    _payloadFingerprintSalt = salt;
    _saltGenerationFailureTimestamp = undefined;
    return salt;
  })();

  try {
    const saltResult = await _payloadFingerprintSaltPromise;
    return saltResult;
  } finally {
    // clear promise so subsequent calls go fast (salt is cached)
    _payloadFingerprintSaltPromise = undefined;
  }
}

// Helper: compute an initial allowed origin from an incoming MessageEvent.
// This mirrors the small, well-audited logic used by workers to lock the
// inbound origin at initialization time. We expose it so callers can reuse
// identical semantics instead of re-implementing them.
export function computeInitialAllowedOrigin(
  event?: MessageEvent,
): string | undefined {
  try {
    const origin =
      event && typeof event.origin === "string" ? event.origin : "";
    if (origin) return origin;
    if (typeof location !== "undefined" && typeof location.origin === "string")
      return location.origin;
    return undefined;
  } catch {
    return undefined;
  }
}

// Helper: check whether an incoming MessageEvent should be accepted given a
// locked origin (if any). This implements the conservative fallback behavior
// used by workers: if a locked origin exists, require a match; otherwise
// fall back to matching location.origin when possible; if origin information
// is unavailable, require the presence of a reply MessagePort to avoid
// accepting anonymous posts.
export function isEventAllowedWithLock(
  event: MessageEvent,
  lockedOrigin?: string,
): boolean {
  try {
    const incomingOrigin = typeof event.origin === "string" ? event.origin : "";

    if (typeof lockedOrigin === "string" && lockedOrigin !== "") {
      return incomingOrigin === lockedOrigin;
    }

    const fallbackOrigin =
      typeof location !== "undefined" ? location.origin : "";
    if (incomingOrigin !== "" && fallbackOrigin !== "") {
      return incomingOrigin === fallbackOrigin;
    }

    // If we can't establish any origin information, only accept messages that
    // include a reply port — this avoids processing anonymous posts.
    return Array.isArray(event.ports) && event.ports.length > 0;
  } catch {
    return false;
  }
}

async function getPayloadFingerprint(data: unknown): Promise<string> {
  // Canonicalize sanitized payload for deterministic fingerprints
  const sanitized: unknown = (() => {
    try {
      return toNullProto(data, 0, _pmCfg().maxPayloadDepth);
    } catch {
      // If sanitization fails, fall back to raw representation for diagnostics only
      return data;
    }
  })();
  const stable = stableStringify(
    sanitized,
    _pmCfg().maxPayloadDepth,
    _pmCfg().maxTraversalNodes,
  );
  if (!stable.ok) {
    // If canonicalization fails, return an explicit error token in prod or a fallback in dev
    if (environment.isProduction)
      throw new EncodingError(
        "Fingerprinting failed due to resource constraints",
      );
    // dev/test fallback: use best-effort raw string truncated

    const s = JSON.stringify(sanitized).slice(0, _pmCfg().maxPayloadBytes);
    return computeFingerprintFromString(s);
  }
  // Encode as UTF-8 bytes and truncate by bytes to avoid splitting multi-byte chars
  const fullBytes = SHARED_ENCODER.encode(stable.s);
  const payloadBytes = fullBytes.slice(0, _pmCfg().maxPayloadBytes);
  return computeFingerprintFromBytes(payloadBytes);
}

// Common fingerprint computation logic shared between functions
async function computeFingerprintFromBytes(
  payloadBytes: Uint8Array,
): Promise<string> {
  // eslint-disable-next-line functional/no-let -- Local salt buffer variable; scoped to function
  let saltBuf: Uint8Array | undefined;
  try {
    saltBuf = await ensureFingerprintSalt();
  } catch {
    if (environment.isProduction)
      throw new InvalidConfigurationError("Fingerprinting unavailable");
  }

  try {
    const crypto = await ensureCrypto();
    const c = crypto as Crypto & {
      readonly subtle?: { readonly digest?: unknown };
    };
    const hasDigest = typeof c.subtle.digest === "function";
    if (hasDigest && saltBuf) {
      const subtle = c.subtle as unknown as SubtleCrypto;
      const input = new Uint8Array(saltBuf.length + payloadBytes.length);
      input.set(saltBuf, 0);
      input.set(payloadBytes, saltBuf.length);
      const digest = await subtle.digest("SHA-256", input.buffer);
      return arrayBufferToBase64(digest).slice(0, 12);
    }
  } catch {
    /* fall through to non-crypto fallback */
  }

  // Fallback: salted non-crypto rolling hash (development/test only)
  if (!saltBuf) return "FINGERPRINT_ERR";
  const sb = saltBuf;
  // eslint-disable-next-line functional/no-let -- Local accumulator for hash computation; scoped to function
  let accumulator = 2166136261 >>> 0; // FNV-1a init
  for (const byte of sb) {
    accumulator = ((accumulator ^ byte) * 16777619) >>> 0;
  }
  for (const byte of payloadBytes) {
    accumulator = ((accumulator ^ byte) * 16777619) >>> 0;
  }
  return accumulator.toString(16).padStart(8, "0");
}

// Extracted helper so stable/canonical fallback can use the same compute logic
async function computeFingerprintFromString(s: string): Promise<string> {
  // Work with UTF-8 bytes and prefer crypto.subtle when available.
  const fullBytes = SHARED_ENCODER.encode(s);
  const payloadBytes = fullBytes.slice(0, _pmCfg().maxPayloadBytes);

  return computeFingerprintFromBytes(payloadBytes);
}

export function _validatePayload(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
): { readonly valid: boolean; readonly reason?: string } {
  if (typeof validator === "function") {
    try {
      return { valid: validator(data) };
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Validator function threw: ${error instanceof Error ? error.message : ""}`,
      };
    }
  }
  const isPlainOrNullObject = (o: unknown): o is Record<string, unknown> => {
    if (o === null || typeof o !== "object") return false;
    const p = Object.getPrototypeOf(o) as object | null | undefined;
    return p === Object.prototype || p === null;
  };
  if (!isPlainOrNullObject(data)) {
    return { valid: false, reason: `Expected object, got ${typeof data}` };
  }
  const plainData = data;
  const keys = Object.keys(plainData);
  if (keys.some((k) => isForbiddenKey(k))) {
    return { valid: false, reason: "Forbidden property name present" };
  }
  for (const [key, expectedType] of Object.entries(validator)) {
    if (!Object.hasOwn(plainData, key)) {
      return { valid: false, reason: `Missing property '${key}'` };
    }
    const value = plainData[key];
    const actualType = Array.isArray(value) ? "array" : typeof value;
    if (actualType !== expectedType) {
      return {
        valid: false,
        reason: `Property '${key}' has wrong type. Expected ${expectedType}, got ${actualType}`,
      };
    }
  }
  return { valid: true };
}

export function _validatePayloadWithExtras(
  data: unknown,
  validator: ((d: unknown) => boolean) | Record<string, SchemaValue>,
  allowExtraProperties = false,
): { readonly valid: boolean; readonly reason?: string } {
  // Validator function path: execute safely and return boolean result.
  if (typeof validator === "function") {
    try {
      return { valid: (validator as (d: unknown) => boolean)(data) };
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Validator function threw: ${error instanceof Error ? error.message : ""}`,
      };
    }
  }

  // For schema validators, reuse the base validation first.
  const base = _validatePayload(data, validator);
  if (!base.valid) return base;

  // If extra properties are allowed, we're done.
  if (allowExtraProperties) return { valid: true };

  // Otherwise, ensure no unexpected keys are present.
  const allowed = new Set(Object.keys(validator));
  const plainData = data as Record<string, unknown>;
  for (const k of Object.keys(plainData)) {
    if (!allowed.has(k)) {
      return { valid: false, reason: `Unexpected property '${k}'` };
    }
  }

  return { valid: true };
}

// Test-only accessors for internal helpers. Guarded by a runtime check to avoid
// leaking internals in production builds. These are only available when the
// build defines `__TEST__` and the runtime allows test APIs via dev-guards.
/* eslint-disable sonarjs/cognitive-complexity -- Audited: guarded test internals exposure with multiple environment gates; refactoring may obscure safety checks. */
export const __test_internals:
  | {
      readonly toNullProto: (
        object: unknown,
        depth?: number,
        maxDepth?: number,
      ) => unknown;
      readonly getPayloadFingerprint: (data: unknown) => Promise<string>;
      readonly ensureFingerprintSalt: () => Promise<Uint8Array>;
      readonly deepFreeze: <T>(object: T) => T;
    }
  | undefined = (() => {
  // Only expose internals when built explicitly for tests.
  const isTestBuild = (() => {
    try {
      return typeof __TEST__ !== "undefined" && __TEST__;
    } catch {
      return false;
    }
  })();

  // Resolve environment and allow flags up-front for consistent decisions
  const isProduction = (() => {
    try {
      return environment.isProduction;
    } catch {
      return false;
    }
  })();
  const environmentAllow =
    typeof process !== "undefined" &&
    (process as unknown as { env?: Record<string, string | undefined> }).env?.[
      "SECURITY_KIT_ALLOW_TEST_APIS"
    ] === "true";
  const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
    "__SECURITY_KIT_ALLOW_TEST_APIS"
  ];

  // If build-time macro is absent, allow exposure only when explicitly allowed in
  // non-production via env/global flags. Otherwise, stay undefined.
  if (!isTestBuild) {
    if (!isProduction && (environmentAllow || globalAllow)) {
      return {
        toNullProto: toNullProto as (
          object: unknown,
          depth?: number,
          maxDepth?: number,
        ) => unknown,
        getPayloadFingerprint: getPayloadFingerprint as (
          data: unknown,
        ) => Promise<string>,
        ensureFingerprintSalt:
          ensureFingerprintSalt as () => Promise<Uint8Array>,
        deepFreeze: deepFreeze as <T>(object: T) => T,
      };
    }
    return;
  }

  // Helper to construct the internals object.
  const exportsObject = () => ({
    toNullProto: toNullProto as (
      object: unknown,
      depth?: number,
      maxDepth?: number,
    ) => unknown,
    getPayloadFingerprint: getPayloadFingerprint as (
      data: unknown,
    ) => Promise<string>,
    ensureFingerprintSalt: ensureFingerprintSalt as () => Promise<Uint8Array>,
    deepFreeze: deepFreeze as <T>(object: T) => T,
  });

  try {
    // In production, require explicit allow; otherwise, do not expose.
    if (isProduction && !(environmentAllow || globalAllow)) return;

    const request = (globalThis as unknown as Record<string, unknown>)[
      "require"
    ];
    if (typeof request === "function") {
      try {
        const invoke = request as unknown as (id: string) => unknown;
        const developmentGuards = invoke("./development-guards") as {
          readonly assertTestApiAllowed: () => void;
        };
        developmentGuards.assertTestApiAllowed();
        return exportsObject();
      } catch (guardError) {
        // Fail-closed in production: if guard cannot be loaded or assertion fails,
        // do NOT expose internals even when explicit flags are set.
        if (!isProduction && (environmentAllow || globalAllow))
          return exportsObject();
        // In production, fail closed without logging underlying guard error details
        // to reduce potential side-channel surface (e.g., timing/log content probing).
        if (!isProduction) {
          try {
            secureDevelopmentLog(
              "warn",
              "postMessage",
              "Development guard prevented exposing test internals",
              { error: sanitizeErrorForLogs(guardError) },
            );
          } catch {
            /* ignore */
          }
        }
        return;
      }
    }
    // If require is not available: allow exposure only in non-production
    // when an explicit allow flag is set; otherwise, do not expose.
    if (!isProduction && (environmentAllow || globalAllow))
      return exportsObject();
    return;
  } catch (error: unknown) {
    // On unexpected errors: do not expose in production; in non-production,
    // expose only if explicitly allowed via env/global flag.
    try {
      const isProduction_ = environment.isProduction;
      if (isProduction_) return;
    } catch {
      /* ignore */
    }
    try {
      secureDevelopmentLog(
        "warn",
        "postMessage",
        "Error while determining test internals exposure",
        { error: sanitizeErrorForLogs(error) },
      );
    } catch {
      /* ignore */
    }
    return environmentAllow || globalAllow ? exportsObject() : undefined;
  }
})();
/* eslint-enable sonarjs/cognitive-complexity */

// Runtime-guarded test helpers: these call a runtime dev-guard to ensure they
// are not used in production by accident. Prefer these in unit tests instead
// of relying on build-time __TEST__ macros which may not be available in all
// execution environments used by test runners.
function _assertTestApiAllowedInline(): void {
  try {
    if (!environment.isProduction) return;
  } catch {
    return;
  }
  const environmentAllow =
    typeof process !== "undefined" &&
    (process as unknown as { env?: Record<string, string | undefined> }).env?.[
      "SECURITY_KIT_ALLOW_TEST_APIS"
    ] === "true";
  const globalAllow = !!(globalThis as unknown as Record<string, unknown>)[
    "__SECURITY_KIT_ALLOW_TEST_APIS"
  ];
  if (environmentAllow || globalAllow) return;
  throw new Error(
    "Test-only APIs are disabled in production. Set SECURITY_KIT_ALLOW_TEST_APIS=true or set globalThis.__SECURITY_KIT_ALLOW_TEST_APIS = true to explicitly allow.",
  );
}

export function __test_getPayloadFingerprint(data: unknown): Promise<string> {
  _assertTestApiAllowedInline();
  return getPayloadFingerprint(data);
}

export function __test_ensureFingerprintSalt(): Promise<Uint8Array> {
  _assertTestApiAllowedInline();
  return ensureFingerprintSalt();
}

export function __test_toNullProto(
  object: unknown,
  depth?: number,
  maxDepth?: number,
): unknown {
  _assertTestApiAllowedInline();
  return toNullProto(object, depth ?? 0, maxDepth ?? _pmCfg().maxPayloadDepth);
}

export function __test_deepFreeze<T>(object: T): T {
  _assertTestApiAllowedInline();
  return deepFreeze(object);
}

export function __test_resetForUnitTests(): void {
  _assertTestApiAllowedInline();
  _payloadFingerprintSalt = undefined;
  _diagnosticsDisabledDueToNoCryptoInProduction = false;
  _saltGenerationFailureTimestamp = undefined;
}

// Test-only helpers to inspect and manipulate the salt failure timestamp for
// adversarial tests that simulate cooldown behavior. Guarded by the same
// runtime test API check used above.
export function __test_getSaltFailureTimestamp(): number | undefined {
  _assertTestApiAllowedInline();
  return _saltGenerationFailureTimestamp;
}

export function __test_setSaltFailureTimestamp(v: number | undefined): void {
  _assertTestApiAllowedInline();
  _saltGenerationFailureTimestamp = v;
}
