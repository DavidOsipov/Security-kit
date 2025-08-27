// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure URL and URI construction and parsing utilities.
 * Fully linted & typesafe to match strict TS + ESLint rules provided.
 *
 * Key hardening changes vs prior version:
 * - strict runtime type checks for parameter objects/Maps (fail-fast)
 * - removed all `null` literals (uses `??` instead)
 * - rejects URLs containing embedded credentials
 * - canonical path-segment encoding before appending
 * - sanitized error messages in production via environment.isProduction
 * - clearer allowedSchemes intersection failure - explicit error
 *
 * This file assumes the following imports exist in your project:
 *  - InvalidParameterError from "./errors"
 *  - isForbiddenKey, getForbiddenKeys from "./constants"
 *  - getSafeSchemes from "./url-policy"
 *  - environment from "./environment"
 *  - secureDevLog as secureDevelopmentLog from "./utils"
 *
 * The module is written to satisfy strict TypeScript + your lint rules.
 */

import { InvalidParameterError } from "./errors";
import { isForbiddenKey, getForbiddenKeys } from "./constants";
import { getSafeSchemes } from "./url-policy";
import { environment } from "./environment";
import { secureDevLog as secureDevelopmentLog } from "./utils";

/* -------------------------
   Utilities & helpers
   ------------------------- */

/**
 * Convert unknown to safe string. Collapses undefined (and previously null)
 * to empty string. Avoids using literal `null`.
 */
const _toString = (v: unknown): string => String(v ?? "");

/**
 * Create a safe error message that avoids leaking internal details in production.
 */
function makeSafeError(publicMessage: string, error: unknown): string {
  if (!environment.isProduction) {
    return `${publicMessage}: ${error instanceof Error ? error.message : String(error)}`;
  }
  return publicMessage;
}

/**
 * Determine canonical scheme (ensures trailing ':').
 */
function canonicalizeScheme(s: string): string {
  const sString = String(s).trim();
  return sString.endsWith(":")
    ? sString.toLowerCase()
    : `${sString.toLowerCase()}:`;
}

/* -------------------------
   Origin normalization
   ------------------------- */

/**
 * Normalize an origin string to canonical `protocol//host[:port]` form.
 * Throws InvalidParameterError if the input cannot be parsed as an absolute origin.
 */
export function normalizeOrigin(o: string): string {
  if (typeof o !== "string" || o.length === 0) {
    throw new InvalidParameterError("Origin must be a non-empty string.");
  }
  try {
    const u = new URL(o);
    ensureNoCredentials(u, "normalizeOrigin");
    const proto = u.protocol; // includes trailing ':'
    const hostname = u.hostname.toLowerCase();
    const port = u.port;
    const defaultPorts: Record<string, string> = {
      "http:": "80",
      "https:": "443",
    };
    const includePort = port !== "" && port !== defaultPorts[proto];
    const portPart = includePort ? `:${port}` : "";
    return `${proto}//${hostname}${portPart}`;
  } catch (error: unknown) {
    throw new InvalidParameterError(makeSafeError("Invalid origin", error));
  }
}

/* -------------------------
   Scheme policy helpers
   ------------------------- */

function _isMapLike(x: unknown): x is ReadonlyMap<string, unknown> {
  // Cross-realm-safe Map detection
  return (
    Object.prototype.toString.call(x) === "[object Map]" || x instanceof Map
  );
}

function _isPlainObject(x: unknown): x is Record<string, unknown> {
  return Object.prototype.toString.call(x) === "[object Object]";
}

function _isPlainObjectOrMap(
  x: unknown,
): x is Record<string, unknown> | ReadonlyMap<string, unknown> {
  return _isMapLike(x) || _isPlainObject(x);
}

/**
 * Determine effective schemes set.
 * - undefined -> use policy SAFE_SCHEMES
 * - [] -> explicit deny-all
 * - otherwise -> canonicalized intersection of caller list and policy
 *
 * Throws if caller requested allowedSchemes that have zero intersection with policy,
 * since silent deny-all is surprising and may break callers unintentionally.
 */
function getEffectiveSchemes(
  allowedSchemes?: readonly string[],
): ReadonlySet<string> {
  const SAFE_SCHEMES = new Set(getSafeSchemes().map(canonicalizeScheme));
  if (allowedSchemes === undefined) return SAFE_SCHEMES;
  if (Array.isArray(allowedSchemes) && allowedSchemes.length === 0)
    return new Set<string>(); // explicit deny-all

  const userSet = new Set(Array.from(allowedSchemes).map(canonicalizeScheme));
  const intersection = new Set([...userSet].filter((s) => SAFE_SCHEMES.has(s)));
  if (userSet.size > 0 && intersection.size === 0) {
    throw new InvalidParameterError(
      "No allowedSchemes remain after applying policy; intersection is empty.",
    );
  }
  // Do not implicitly widen in development or production: intersection is the correct result.
  return intersection;
}

/* -------------------------
   Dangerous key checking
   ------------------------- */

/**
 * Shared global dangerous keys (cached)
 */
const GLOBAL_DANGEROUS_KEYS = new Set([
  ...getForbiddenKeys(),
  "__proto__",
  "constructor",
  "prototype",
]);

/**
 * Check for dangerous keys in a plain object or Map.
 * - Asserts that the input is a plain object or Map (fail-fast).
 * - Throws InvalidParameterError on unsafe findings, or logs and throws (strict).
 */
function _checkForDangerousKeys(
  object: unknown,
  onUnsafeKey: UnsafeKeyAction,
  componentName: string,
  baseReference: string,
): asserts object is Record<string, unknown> | ReadonlyMap<string, unknown> {
  if (!_isPlainObjectOrMap(object)) {
    const message = `Unsafe parameter type provided to ${componentName}. Must be a plain object or Map.`;
    if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
    secureDevelopmentLog("warn", componentName, message, {
      base: baseReference,
    });
    // Strict library: do not proceed
    throw new InvalidParameterError(message);
  }

  // If Map, check keys using Map API
  if (_isMapLike(object)) {
    for (const dangerous of GLOBAL_DANGEROUS_KEYS) {
      if (object.has(dangerous)) {
        const message = `Unsafe key '${dangerous}' present in ${componentName} map.`;
        if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
        secureDevelopmentLog("warn", componentName, message, {
          base: baseReference,
          dangerous,
        });
        throw new InvalidParameterError(message);
      }
    }
    return;
  }

  // Now object is a plain object
  const ownPropertyNames = Object.getOwnPropertyNames(object);
  const ownKeysSet = new Set<string>(ownPropertyNames);
  for (const dangerous of GLOBAL_DANGEROUS_KEYS) {
    if (dangerous === "__proto__") {
      if (Object.prototype.hasOwnProperty.call(object, "__proto__")) {
        const message = `Unsafe key '__proto__' present on ${componentName} object.`;
        if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
        secureDevelopmentLog("warn", componentName, message, {
          base: baseReference,
        });
        throw new InvalidParameterError(message);
      }
      continue;
    }
    if (ownKeysSet.has(dangerous)) {
      const message = `Unsafe key '${dangerous}' present on ${componentName} object.`;
      if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
      secureDevelopmentLog("warn", componentName, message, {
        base: baseReference,
        dangerous,
      });
      throw new InvalidParameterError(message);
    }
  }

  // Warn if any symbol keys exist (we ignore them but log)
  const symbolKeys = Object.getOwnPropertySymbols(object);
  if (symbolKeys.length > 0) {
    secureDevelopmentLog(
      "warn",
      componentName,
      "Object contains symbol keys; these will be ignored.",
      {
        base: baseReference,
        symbolCount: symbolKeys.length,
      },
    );
  }
}

/* -------------------------
   Query & update parameter processing
   ------------------------- */

type ParameterType = "string" | "number" | "boolean";
type UnsafeKeyAction = "throw" | "warn" | "skip";

/**
 * Process query parameters for createSecureURL.
 * Uses Map or plain object; enforces safe keys and appends to url.searchParams.
 */
function processQueryParameters(
  url: URL,
  parameters: Record<string, unknown> | ReadonlyMap<string, unknown>,
  onUnsafeKey: UnsafeKeyAction,
  base: string,
): void {
  _checkForDangerousKeys(parameters, onUnsafeKey, "createSecureURL", base);

  const entries: Iterable<readonly [string, unknown]> = _isMapLike(parameters)
    ? parameters.entries()
    : Object.entries(parameters);

  for (const [key, value] of entries) {
    const unsafe = isForbiddenKey(key) || !isSafeKey(key);
    if (unsafe) {
      const message = `Skipping unsafe query key '${key}' when building URL.`;
      if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
      if (onUnsafeKey === "warn")
        secureDevelopmentLog("warn", "createSecureURL", message, { base, key });
      // if 'skip' or 'warn', simply continue (but in strict library warn triggers thrown earlier)
      continue;
    }
    const stringValue = value === undefined ? "" : String(value ?? "");
    url.searchParams.append(key, stringValue);
  }
}

/**
 * Process update parameters for updateURLParams.
 */
function processUpdateParameters(
  url: URL,
  updates: Record<string, unknown> | ReadonlyMap<string, unknown>,
  removeUndefined: boolean,
  onUnsafeKey: UnsafeKeyAction,
  baseUrl: string,
): void {
  _checkForDangerousKeys(updates, onUnsafeKey, "updateURLParams", baseUrl);

  const entries: Iterable<readonly [string, unknown]> = _isMapLike(updates)
    ? updates.entries()
    : Object.entries(updates);

  for (const [key, value] of entries) {
    if (isForbiddenKey(key) || !isSafeKey(key)) {
      const message = `Skipping unsafe query key '${key}' when updating URL.`;
      if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
      if (onUnsafeKey === "warn")
        secureDevelopmentLog("warn", "updateURLParams", message, {
          baseUrl,
          key,
        });
      continue;
    }

    if (value === undefined && removeUndefined) {
      url.searchParams.delete(key);
      continue;
    }

    // Treat nullish as empty string for updates (preserving prior behavior); avoid null literal.
    url.searchParams.set(key, String(value ?? ""));
  }
}

/* -------------------------
   Path segments & encoding
   ------------------------- */

const ENCODE_SUBDELIMS_RE = /[!'()*]/g;

function hasControlChars(s: string): boolean {
  for (let index = 0; index < s.length; index += 1) {
    const code = s.charCodeAt(index);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f))
      return true;
  }
  return false;
}

const _hex = (c: string) =>
  "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");

function _rfc3986EncodeURIComponentImpl(value: unknown): string {
  const s = _toString(value);
  if (hasControlChars(s))
    throw new InvalidParameterError(
      "Input contains forbidden control characters.",
    );
  return encodeURIComponent(s).replace(ENCODE_SUBDELIMS_RE, _hex);
}

export const encodeComponentRFC3986 = _rfc3986EncodeURIComponentImpl;
export const encodePathSegment = _rfc3986EncodeURIComponentImpl;
export const encodeQueryValue = _rfc3986EncodeURIComponentImpl;
export const encodeMailtoValue = _rfc3986EncodeURIComponentImpl;

export function encodeFormValue(value: unknown): string {
  return _rfc3986EncodeURIComponentImpl(value).replace(/%20/g, "+");
}

/**
 * Append path segments to URL. Validates decoded segment and appends encoded form.
 */
function appendPathSegments(url: URL, pathSegments: readonly string[]): void {
  for (const segment of pathSegments) {
    if (
      typeof segment !== "string" ||
      segment.length === 0 ||
      segment.length > 1024
    ) {
      throw new InvalidParameterError(
        "Path segments must be non-empty strings shorter than 1024 chars.",
      );
    }

    // Validate decoded segment against traversal chars
    const decoded = strictDecodeURIComponentOrThrow(segment);
    if (
      decoded.includes("/") ||
      decoded.includes("\\") ||
      decoded === "." ||
      decoded === ".."
    ) {
      throw new InvalidParameterError(
        "Path segments must not contain separators or navigation.",
      );
    }

    const encoded = encodePathSegment(segment);
    if (!url.pathname.endsWith("/")) url.pathname += "/";
    url.pathname += encoded;
  }
}

/* -------------------------
   Dangerous key helper + safe key regex
   ------------------------- */

const SAFE_KEY_REGEX = /^[\w.-]{1,128}$/;
function isSafeKey(key: string): boolean {
  return (
    SAFE_KEY_REGEX.test(key) &&
    key !== "__proto__" &&
    key !== "constructor" &&
    key !== "prototype"
  );
}

/* -------------------------
   Credential rejection helper
   ------------------------- */

function ensureNoCredentials(url: URL, context: string): void {
  if (url.username || url.password) {
    throw new InvalidParameterError(
      `${context}: URLs containing embedded credentials are not allowed.`,
    );
  }
}

/* -------------------------
   Public APIs
   ------------------------- */

/**
 * createSecureURL - constructs a safe, normalized URL string or throws.
 */
export function createSecureURL(
  base: string,
  pathSegments: readonly string[] = [],
  queryParameters: Record<string, unknown> | ReadonlyMap<string, unknown> = {},
  fragment?: string,
  options: {
    readonly requireHTTPS?: boolean;
    readonly allowedSchemes?: readonly string[]; // e.g. ["https:", "mailto:"]
    readonly maxLength?: number;
    readonly onUnsafeKey?: UnsafeKeyAction;
  } = {},
): string {
  if (typeof base !== "string" || base.length === 0) {
    throw new InvalidParameterError("Base URL must be a non-empty string.");
  }

  try {
    const url = new URL(base);
    ensureNoCredentials(url, "createSecureURL");
    appendPathSegments(url, pathSegments);

    const {
      allowedSchemes,
      maxLength: maxLengthOpt,
      onUnsafeKey = "throw",
      requireHTTPS = false,
    } = options;

    // Validate query object and add params
    processQueryParameters(url, queryParameters, onUnsafeKey, base);

    // Enforce requireHTTPS if requested
    if (requireHTTPS && canonicalizeScheme(url.protocol) !== "https:") {
      throw new InvalidParameterError(
        "HTTPS is required but URL scheme is not 'https:'.",
      );
    }

    enforceSchemeAndLength(url, allowedSchemes, maxLengthOpt);

    if (fragment !== undefined) {
      if (typeof fragment !== "string")
        throw new InvalidParameterError("Fragment must be a string.");
      if (hasControlChars(fragment))
        throw new InvalidParameterError(
          "Fragment contains control characters.",
        );
      // Set without leading '#'
      url.hash = fragment;
    }

    return url.href;
  } catch (error: unknown) {
    throw new InvalidParameterError(makeSafeError("Invalid base URL", error));
  }
}

/**
 * updateURLParams - update/patch the query part of an existing URL string.
 */
export function updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown> | ReadonlyMap<string, unknown>,
  options: {
    readonly removeUndefined?: boolean;
    readonly requireHTTPS?: boolean;
    readonly allowedSchemes?: readonly string[];
    readonly maxLength?: number;
    readonly onUnsafeKey?: UnsafeKeyAction;
  } = {},
): string {
  const { removeUndefined = true } = options;
  if (typeof baseUrl !== "string")
    throw new InvalidParameterError("Base URL must be a string.");
  try {
    const url = new URL(baseUrl);
    ensureNoCredentials(url, "updateURLParams");

    const {
      onUnsafeKey = "throw",
      requireHTTPS: requireHTTPSOpt = false,
      allowedSchemes,
      maxLength: maxLengthOpt,
    } = options;

    _checkForDangerousKeys(updates, onUnsafeKey, "updateURLParams", baseUrl);

    processUpdateParameters(
      url,
      updates,
      removeUndefined,
      onUnsafeKey,
      baseUrl,
    );

    if (requireHTTPSOpt && canonicalizeScheme(url.protocol) !== "https:") {
      throw new InvalidParameterError(
        "HTTPS is required but URL scheme is not 'https:'.",
      );
    }

    if (typeof maxLengthOpt === "number" && url.href.length > maxLengthOpt) {
      throw new InvalidParameterError(
        `Resulting URL exceeds maxLength ${maxLengthOpt}.`,
      );
    }

    enforceSchemeAndLength(url, allowedSchemes, maxLengthOpt);

    return url.href;
  } catch (error: unknown) {
    throw new InvalidParameterError(makeSafeError("Invalid base URL", error));
  }
}

/**
 * validateURLStrict - convenience wrapper that demands HTTPS and returns {ok|error}
 */
export function validateURLStrict(
  urlString: string,
  options: {
    readonly allowedOrigins?: readonly string[];
    readonly maxLength?: number;
  } = {},
):
  | { readonly ok: true; readonly url: URL }
  | { readonly ok: false; readonly error: Error } {
  // Build options while avoiding explicitly passing `undefined` for optional fields
  const args = {
    requireHTTPS: true,
    ...(options.allowedOrigins ? { allowedOrigins: options.allowedOrigins } : {}),
    ...(options.maxLength ? { maxLength: options.maxLength } : {}),
  } as const;
  return validateURL(urlString, args as unknown as {
    readonly allowedOrigins?: readonly string[];
    readonly requireHTTPS?: boolean;
    readonly allowedSchemes?: readonly string[];
    readonly maxLength?: number;
  });
}

/**
 * validateURL - validate URL string and return parsed URL or error object.
 * Does NOT throw; returns a structured result (use createSecureURL for throwing API).
 */
export function validateURL(
  urlString: string,
  options: {
    readonly allowedOrigins?: readonly string[];
    readonly requireHTTPS?: boolean;
    readonly allowedSchemes?: readonly string[];
    readonly maxLength?: number;
  } = {},
):
  | { readonly ok: true; readonly url: URL }
  | { readonly ok: false; readonly error: Error } {
  const {
    allowedOrigins,
    allowedSchemes,
    maxLength = 2048,
    requireHTTPS = false,
  } = options;

  if (typeof urlString !== "string") {
    return {
      ok: false,
      error: new InvalidParameterError("URL must be a string."),
    };
  }
  if (urlString.length > maxLength) {
    return {
      ok: false,
      error: new InvalidParameterError(`URL length exceeds ${maxLength}.`),
    };
  }

  try {
    const url = new URL(urlString);
    ensureNoCredentials(url, "validateURL");

    if (requireHTTPS && canonicalizeScheme(url.protocol) !== "https:") {
      return {
        ok: false,
        error: new InvalidParameterError("HTTPS is required."),
      };
    }

    // Validate scheme against effective schemes
    const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
    if (!effectiveSchemes.has(canonicalizeScheme(url.protocol))) {
      return {
        ok: false,
        error: new InvalidParameterError(
          `URL scheme '${canonicalizeScheme(url.protocol)}' is not allowed.`,
        ),
      };
    }

    // Validate origin allowlist
    if (!isOriginAllowed(url.origin, allowedOrigins)) {
      return {
        ok: false,
        error: new InvalidParameterError(
          `URL origin '${url.origin}' is not in allowlist.`,
        ),
      };
    }

    return { ok: true, url };
  } catch (error: unknown) {
    return {
      ok: false,
      error: new InvalidParameterError(makeSafeError("Malformed URL", error)),
    };
  }
}

/* -------------------------
   parseURLParams
   ------------------------- */

export function parseURLParams(urlString: string): Record<string, string>;
export function parseURLParams<K extends string>(
  urlString: string,
  expectedParameters: Record<K, ParameterType>,
): Partial<Record<K, string>> & Record<string, string>;
export function parseURLParams(
  urlString: string,
  expectedParameters?: Record<string, ParameterType>,
): Record<string, string> {
  if (typeof urlString !== "string")
    throw new InvalidParameterError("URL must be a string.");

  const parseUrlOrThrow = (s: string): URL => {
    try {
      const url = new URL(s);
      ensureNoCredentials(url, "parseURLParams");
      return url;
    } catch (error: unknown) {
      throw new InvalidParameterError(makeSafeError("Invalid URL", error));
    }
  };

  const url = parseUrlOrThrow(urlString);

  const parameterMap = new Map<string, string>();
  for (const [key, value] of url.searchParams.entries()) {
    if (isSafeKey(key)) parameterMap.set(key, value);
  }

  // Validate expected parameters
  if (expectedParameters)
    _validateExpectedParameters(expectedParameters, urlString, parameterMap);

  // Freeze and return a POJO with a null prototype created from the map so
  // callers can assert the prototype is null to detect tampering.
  const object = Object.create(null) as Record<string, string>;
  for (const [k, v] of parameterMap.entries()) object[k] = v;
  return Object.freeze(object);
}

function _logParameterWarn(
  kind: string,
  key: string,
  urlString: string,
  extra?: string,
): void {
  secureDevelopmentLog(
    "warn",
    "parseURLParams",
    extra ? `${kind} '${key}': ${extra}` : `${kind} '${key}'`,
    { url: urlString },
  );
}

function _validateExpectedParameters(
  expected: Record<string, ParameterType>,
  urlString: string,
  parameterMap: ReadonlyMap<string, string>,
): void {
  for (const [expectedKey, expectedType] of Object.entries(expected)) {
    const value = parameterMap.get(expectedKey);
    if (value === undefined) {
      _logParameterWarn(
        "Expected parameter is missing",
        expectedKey,
        urlString,
      );
    } else if (expectedType === "number" && Number.isNaN(Number(value))) {
      _logParameterWarn(
        "Parameter expected number",
        expectedKey,
        urlString,
        `got '${value}'`,
      );
    }
  }
}

/* -------------------------
   RFC3986 utilities - decoding
   ------------------------- */

const MAX_DECODE_INPUT_LEN = 4096;

export function strictDecodeURIComponent(
  string_: string,
):
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly error: Error } {
  try {
    const input = _toString(string_);
    if (input.length > MAX_DECODE_INPUT_LEN) {
      return {
        ok: false,
        error: new InvalidParameterError("URI component is too long"),
      };
    }
    const decoded = decodeURIComponent(input);
    if (hasControlChars(decoded)) {
      return {
        ok: false,
        error: new InvalidParameterError(
          "Decoded URI component contains control characters",
        ),
      };
    }
    return { ok: true, value: decoded };
  } catch {
    return {
      ok: false,
      error: new InvalidParameterError("URI component is malformed"),
    };
  }
}

export function strictDecodeURIComponentOrThrow(string_: string): string {
  const res = strictDecodeURIComponent(string_);
  if (!res.ok) throw res.error;
  return res.value;
}

/* -------------------------
   IDNA helper
   ------------------------- */

export function encodeHostLabel(
  label: string,
  idnaLibrary: { readonly toASCII: (s: string) => string },
): string {
  if (!idnaLibrary?.toASCII)
    throw new InvalidParameterError(
      "An IDNA-compliant library must be provided.",
    );
  return idnaLibrary.toASCII(_toString(label));
}

/* -------------------------
   Helpers used above (re-ordered for clarity)
   ------------------------- */

/**
 * Determine if origin is allowed by allowlist.
 * - undefined -> permissive (useful for backward compatibility)
 * - [] -> explicit deny-all
 */
function isOriginAllowed(
  origin: string,
  allowlist?: readonly string[],
): boolean {
  if (!allowlist) return true;
  if (Array.isArray(allowlist) && allowlist.length === 0) return false;

  const normalized = new Set(allowlist.map((a) => normalizeOrigin(a)));
  const originNorm = normalizeOrigin(origin);
  return normalized.has(originNorm);
}

/**
 * Enforce that url.protocol is allowed and length constraints.
 */
function enforceSchemeAndLength(
  url: URL,
  allowedSchemes?: readonly string[],
  maxLengthOpt?: number,
): void {
  const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
  const protocol = canonicalizeScheme(url.protocol); // ensure canonical form
  if (!effectiveSchemes.has(protocol)) {
    throw new InvalidParameterError(
      `Resulting URL scheme '${protocol}' is not allowed.`,
    );
  }
  if (typeof maxLengthOpt === "number" && url.href.length > maxLengthOpt) {
    throw new InvalidParameterError(
      `Resulting URL exceeds maxLength ${maxLengthOpt}.`,
    );
  }
}
