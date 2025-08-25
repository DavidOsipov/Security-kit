// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure URL and URI construction and parsing utilities.
 * @module
 */

import { InvalidParameterError } from "./errors";
import { isForbiddenKey, getForbiddenKeys } from "./constants";
import { secureDevLog } from "./utils";

// Allowed query/param key pattern and safe-key checker
const SAFE_KEY_REGEX = /^[\w.-]{1,128}$/;
function isSafeKey(key: string): boolean {
  return (
    SAFE_KEY_REGEX.test(key) &&
    key !== "__proto__" &&
    key !== "constructor" &&
    key !== "prototype"
  );
}

// Type alias for expected parameter typing to avoid repeating unions
type ParamType = "string" | "number" | "boolean";
type UnsafeKeyAction = "throw" | "warn" | "skip";

export function normalizeOrigin(o: string): string {
  try {
    const u = new URL(o);
    // Normalize by removing default ports for http/https for consistent allowlist matching
    const proto = u.protocol; // includes trailing ':'
    const hostname = u.hostname.toLowerCase();
    const port = u.port;
    const defaultPorts: Record<string, string> = {
      "http:": "80",
      "https:": "443",
    };
    const includePort = port && port !== defaultPorts[proto];
    const portPart = includePort ? ":" + port : "";
    return `${proto}//${hostname}${portPart}`;
  } catch {
    return o.toLowerCase();
  }
}

function isOriginAllowed(origin: string, allowlist?: string[]): boolean {
  // If caller omitted allowlist -> permissive (backwards compatible).
  // If caller passed an empty array -> deny all (strict, explicit deny).
  if (!allowlist) return true;
  if (Array.isArray(allowlist) && allowlist.length === 0) return false;
  const allowed = new Set(allowlist.map(normalizeOrigin));
  const normalized = normalizeOrigin(origin);
  return allowed.has(normalized);
}

// --- Secure URL Construction ---
// SAFE_SCHEMES is now managed by `src/url-policy.ts` for controlled configuration.
import { getSafeSchemes } from "./url-policy";
import { environment } from "./environment";

function getEffectiveSchemes(allowedSchemes?: string[]): Set<string> {
  const SAFE_SCHEMES = new Set(getSafeSchemes());
  // If caller didn't supply allowedSchemes, just use policy.
  if (!Array.isArray(allowedSchemes) || allowedSchemes.length === 0)
    return SAFE_SCHEMES;

  const userSet = new Set(allowedSchemes.map((s) => String(s)));
  // In production, do not allow callers to expand the global policy. Only
  // allow intersection. In development, be more permissive for DX.
  const intersection = new Set([...userSet].filter((s) => SAFE_SCHEMES.has(s)));
  if (environment.isProduction) return intersection;
  // In non-production, prefer intersection but if intersection is empty, fall
  // back to the SAFE_SCHEMES to avoid accidental denial during development.
  return intersection.size > 0 ? intersection : SAFE_SCHEMES;
}

function enforceSchemeAndLength(
  url: URL,
  allowedSchemes?: string[],
  maxLengthOpt?: number,
): void {
  const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
  if (!effectiveSchemes.has(url.protocol))
    throw new InvalidParameterError(
      `Resulting URL scheme '${url.protocol}' is not allowed.`,
    );
  if (typeof maxLengthOpt === "number" && url.href.length > maxLengthOpt)
    throw new InvalidParameterError(
      `Resulting URL exceeds maxLength ${maxLengthOpt}.`,
    );
}

// Shared set of keys that are never allowed as query or update keys.
const GLOBAL_DANGEROUS_KEYS = new Set([
  ...getForbiddenKeys(),
  "__proto__",
  "constructor",
  "prototype",
]);

function _checkForDangerousKeys(
  obj: Record<string, unknown>,
  onUnsafeKey: UnsafeKeyAction,
  componentName: string,
  baseRef: string,
): void {
  const handleUnsafe = (msg: string, extra?: Record<string, unknown>) => {
    if (onUnsafeKey === "throw") throw new InvalidParameterError(msg);
    if (onUnsafeKey === "warn")
      secureDevLog("warn", componentName, msg, {
        base: baseRef,
        ...(extra || {}),
      });
  };

  const protoIsNull = Object.getPrototypeOf(obj) === null;
  if (Object.prototype.hasOwnProperty.call(obj, "__proto__") || protoIsNull) {
    handleUnsafe(`Unsafe key '__proto__' present on ${componentName} object.`);
  }

  const ownKeyNames = new Set<string>([
    ...Object.keys(obj),
    ...Object.getOwnPropertyNames(obj),
    ...Reflect.ownKeys(obj).map(String),
  ]);

  for (const dangerous of GLOBAL_DANGEROUS_KEYS) {
    if (dangerous === "__proto__") continue;
    if (ownKeyNames.has(dangerous)) {
      handleUnsafe(
        `Unsafe key '${dangerous}' present on ${componentName} object.`,
        {
          dangerous,
        },
      );
    }
  }
}

function processQueryParams(
  url: URL,
  params: Record<string, unknown>,
  onUnsafeKey: UnsafeKeyAction,
  base: string,
): void {
  _checkForDangerousKeys(params, onUnsafeKey, "createSecureURL", base);
  for (const [key, value] of Object.entries(params)) {
    const unsafe = isForbiddenKey(key) || !isSafeKey(key);
    if (unsafe) {
      const msg = `Skipping unsafe query key '${key}' when building URL.`;
      if (onUnsafeKey === "throw") throw new InvalidParameterError(msg);
      if (onUnsafeKey === "warn")
        secureDevLog("warn", "createSecureURL", msg, { base, key });
      continue;
    }
    const stringValue = value == null ? "" : String(value);
    url.searchParams.append(key, stringValue);
  }
}

function processUpdateParams(
  url: URL,
  updates: Record<string, unknown>,
  removeUndefined: boolean,
  onUnsafeKey: UnsafeKeyAction,
  baseUrl: string,
): void {
  _checkForDangerousKeys(updates, onUnsafeKey, "updateURLParams", baseUrl);
  const handleUnsafeKey = (k: string) => {
    const msg = `Skipping unsafe query key '${k}' when updating URL.`;
    if (onUnsafeKey === "throw") throw new InvalidParameterError(msg);
    if (onUnsafeKey === "warn")
      secureDevLog("warn", "updateURLParams", msg, { baseUrl, key: k });
  };

  for (const [key, value] of Object.entries(updates)) {
    if (isForbiddenKey(key) || !isSafeKey(key)) {
      handleUnsafeKey(key);
      continue;
    }

    if (value === undefined && removeUndefined) {
      url.searchParams.delete(key);
      continue;
    }

    url.searchParams.set(key, value === null ? "" : String(value));
  }
}

function appendPathSegments(url: URL, pathSegments: string[]): void {
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

    // 1. Validate the DECODED segment for traversal characters
    const decoded = strictDecodeURIComponentOrThrow(segment);
    if (
      decoded.includes("/") ||
      decoded.includes("\\") ||
      decoded === "." ||
      decoded === ".."
    ) {
      throw new InvalidParameterError(
        `Path segments must not contain separators or navigation.`,
      );
    }

    if (!url.pathname.endsWith("/")) url.pathname += "/";

    // 2. Append the ORIGINAL, RAW segment. The URL API will handle encoding.
    // This prevents double-encoding and ensures characters are handled correctly.
    url.pathname += segment;
  }
}

export function createSecureURL(
  base: string,
  pathSegments: string[] = [],
  queryParams: Record<string, unknown> = {},
  fragment?: string,
  options: {
    requireHTTPS?: boolean;
    allowedSchemes?: string[]; // e.g. ["https:", "mailto:"]
    maxLength?: number;
    onUnsafeKey?: "throw" | "warn" | "skip";
  } = {},
): string {
  if (typeof base !== "string" || base.length === 0) {
    throw new InvalidParameterError("Base URL must be a non-empty string.");
  }
  let url: URL;
  try {
    url = new URL(base);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid base URL: ${base}. ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  appendPathSegments(url, pathSegments);

  const {
    allowedSchemes,
    maxLength: maxLengthOpt,
    onUnsafeKey = "throw",
  } = options;
  // Run a focused dangerous-key check that centralizes prototype-pollution and
  // forbidden-key detection in one place. This keeps the function smaller and
  // easier for auditors to reason about.
  _checkForDangerousKeys(
    queryParams,
    onUnsafeKey as UnsafeKeyAction,
    "createSecureURL",
    base,
  );

  processQueryParams(url, queryParams, onUnsafeKey as UnsafeKeyAction, base);

  // Enforce scheme allowlist and optional max-length in a small helper.
  enforceSchemeAndLength(url, allowedSchemes, maxLengthOpt);

  if (fragment !== undefined) {
    if (typeof fragment !== "string")
      throw new InvalidParameterError("Fragment must be a string.");
    if (hasControlChars(fragment))
      throw new InvalidParameterError("Fragment contains control characters.");
    // URL.hash setter will encode as needed; set without leading '#'
    url.hash = fragment;
  }
  return url.href;
}

export function updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown>,
  options: {
    removeUndefined?: boolean;
    requireHTTPS?: boolean;
    allowedSchemes?: string[];
    maxLength?: number;
    onUnsafeKey?: "throw" | "warn" | "skip";
  } = {},
): string {
  const { removeUndefined = true } = options;
  if (typeof baseUrl !== "string")
    throw new InvalidParameterError("Base URL must be a string.");
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid base URL: ${baseUrl}. ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const {
    onUnsafeKey = "throw",
    requireHTTPS: requireHTTPSOpt,
    allowedSchemes,
    maxLength: maxLengthOpt,
  } = options;

  // Centralized dangerous-key check for update objects.
  _checkForDangerousKeys(
    updates,
    onUnsafeKey as UnsafeKeyAction,
    "updateURLParams",
    baseUrl,
  );

  processUpdateParams(
    url,
    updates,
    removeUndefined,
    onUnsafeKey as UnsafeKeyAction,
    baseUrl,
  );

  if (requireHTTPSOpt) enforceSchemeAndLength(url, allowedSchemes);
  if (typeof maxLengthOpt === "number") {
    if (url.href.length > maxLengthOpt)
      throw new InvalidParameterError(
        `Resulting URL exceeds maxLength ${maxLengthOpt}.`,
      );
  }

  return url.href;
}

export function validateURLStrict(
  urlString: string,
  options: { allowedOrigins?: string[]; maxLength?: number } = {},
): { ok: true; url: URL } | { ok: false; error: Error } {
  const vopts: {
    allowedOrigins?: string[];
    requireHTTPS?: boolean;
    allowedSchemes?: string[];
    maxLength?: number;
  } = {
    // strict variant defaults to HTTPS required
    requireHTTPS: true,
    maxLength: options.maxLength ?? 2048,
  };
  if (options.allowedOrigins !== undefined)
    vopts.allowedOrigins = options.allowedOrigins;
  return validateURL(urlString, vopts);
}

export function validateURL(
  urlString: string,
  options: {
    allowedOrigins?: string[];
    requireHTTPS?: boolean;
    allowedSchemes?: string[];
    maxLength?: number;
  } = {},
): { ok: true; url: URL } | { ok: false; error: Error } {
  const { allowedOrigins, allowedSchemes, maxLength = 2048 } = options;
  if (typeof urlString !== "string")
    return {
      ok: false,
      error: new InvalidParameterError("URL must be a string."),
    };
  if (urlString.length > maxLength)
    return {
      ok: false,
      error: new InvalidParameterError(`URL length exceeds ${maxLength}.`),
    };

  let url: URL;
  try {
    url = new URL(urlString);
  } catch (error) {
    return {
      ok: false,
      error: new InvalidParameterError(
        `Malformed URL: ${error instanceof Error ? error.message : String(error)}`,
      ),
    };
  }

  // Determine effective allowed schemes using centralized helper. This
  // prevents callers from enabling unsafe schemes like 'javascript:' or
  // 'data:' and ensures production-only policy is enforced consistently.
  const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
  if (!effectiveSchemes.has(url.protocol)) {
    return {
      ok: false,
      error: new InvalidParameterError(
        `URL scheme '${url.protocol}' is not allowed.`,
      ),
    };
  }

  if (!isOriginAllowed(url.origin, allowedOrigins))
    return {
      ok: false,
      error: new InvalidParameterError(
        `URL origin '${url.origin}' is not in allowlist.`,
      ),
    };

  return { ok: true, url };
}

function _logParamWarn(
  kind: string,
  key: string,
  urlString: string,
  extra?: string,
): void {
  secureDevLog(
    "warn",
    "parseURLParams",
    extra ? `${kind} '${key}': ${extra}` : `${kind} '${key}'`,
    { url: urlString },
  );
}

function _validateExpectedParams(
  expected: Record<string, ParamType>,
  urlString: string,
  paramMap: Map<string, string>,
): void {
  for (const [expectedKey, expectedType] of Object.entries(expected)) {
    const value = paramMap.get(expectedKey);
    if (value === undefined) {
      _logParamWarn("Expected parameter is missing", expectedKey, urlString);
    } else if (expectedType === "number" && isNaN(Number(value))) {
      _logParamWarn(
        "Parameter expected number",
        expectedKey,
        urlString,
        `got '${value}'`,
      );
    }
  }
}

export function parseURLParams(urlString: string): Record<string, string>;
export function parseURLParams<K extends string>(
  urlString: string,
  expectedParams: Record<K, ParamType>,
): Partial<Record<K, string>> & Record<string, string>;
export function parseURLParams(
  urlString: string,
  expectedParams?: Record<string, ParamType>,
): Record<string, string> {
  if (typeof urlString !== "string")
    throw new InvalidParameterError("URL must be a string.");

  const parseUrlOrThrow = (s: string): URL => {
    try {
      return new URL(s);
    } catch (error) {
      throw new InvalidParameterError(
        `Invalid URL: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  const url = parseUrlOrThrow(urlString);
  const params: Record<string, string> = Object.create(null);
  const paramMap = new Map<string, string>();

  const addParam = (key: string, value: string) => {
    paramMap.set(key, value);
    Object.defineProperty(params, key, {
      value,
      configurable: true,
      enumerable: true,
      writable: false,
    });
  };

  for (const [key, value] of url.searchParams.entries()) {
    if (isSafeKey(key)) addParam(key, value);
  }

  if (expectedParams)
    _validateExpectedParams(expectedParams, urlString, paramMap);
  return Object.freeze(params);
}

// --- RFC 3986 Utilities ---
const ENCODE_SUBDELIMS_RE = /[!'()*]/g;
function hasControlChars(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f))
      return true;
  }
  return false;
}
const _hex = (c: string) =>
  "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
const _toStr = (v: unknown) => (v === null || v === undefined ? "" : String(v));

function _rfc3986EncodeURIComponentImpl(value: unknown): string {
  const s = _toStr(value);
  if (hasControlChars(s)) {
    throw new InvalidParameterError(
      "Input contains forbidden control characters.",
    );
  }
  return encodeURIComponent(s).replace(ENCODE_SUBDELIMS_RE, _hex);
}

export const encodeComponentRFC3986 = _rfc3986EncodeURIComponentImpl;
export const encodePathSegment = _rfc3986EncodeURIComponentImpl;
export const encodeQueryValue = _rfc3986EncodeURIComponentImpl;
export const encodeMailtoValue = _rfc3986EncodeURIComponentImpl;

export function encodeFormValue(value: unknown): string {
  return _rfc3986EncodeURIComponentImpl(value).replace(/%20/g, "+");
}

export function encodeHostLabel(
  label: string,
  idnaLibrary: { toASCII: (s: string) => string },
): string {
  if (!idnaLibrary?.toASCII) {
    throw new InvalidParameterError(
      "An IDNA-compliant library must be provided.",
    );
  }
  return idnaLibrary.toASCII(_toStr(label));
}

export function strictDecodeURIComponent(
  str: string,
): { ok: true; value: string } | { ok: false; error: Error } {
  const MAX_DECODE_INPUT_LEN = 4096;
  try {
    const input = _toStr(str);
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

export function strictDecodeURIComponentOrThrow(str: string): string {
  const res = strictDecodeURIComponent(str);
  if (!res.ok) throw res.error;
  return res.value;
}
