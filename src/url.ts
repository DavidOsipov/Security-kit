// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>

/**
 * Secure URL and URI construction and parsing utilities.
 * @module
 */

import { InvalidParameterError } from "./errors";
import { POSTMESSAGE_FORBIDDEN_KEYS } from "./postMessage";
import { secureDevLog } from "./utils";

// --- Secure URL Construction ---
export function createSecureURL(
  base: string,
  pathSegments: string[] = [],
  queryParams: Record<string, unknown> = {},
  fragment?: string,
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
    url.pathname += encodePathSegment(decoded);
  }

  const SAFE_KEY_REGEX = /^[\w.-]{1,128}$/;
  function isSafeKey(key: string): boolean {
    return (
      SAFE_KEY_REGEX.test(key) &&
      key !== "__proto__" &&
      key !== "constructor" &&
      key !== "prototype"
    );
  }
  const pairs: string[] = [];
  for (const [key, value] of Object.entries(queryParams)) {
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(key) || !isSafeKey(key)) continue;
    const stringValue = value == null ? "" : String(value);
    pairs.push(`${encodeQueryValue(key)}=${encodeQueryValue(stringValue)}`);
  }
  if (pairs.length > 0) {
    url.search =
      (url.search ? `${url.search.slice(1)}&` : "") + pairs.join("&");
  }

  if (fragment !== undefined) {
    if (typeof fragment !== "string")
      throw new InvalidParameterError("Fragment must be a string.");
    url.hash = fragment;
  }
  return url.href;
}

export function updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown>,
  options: { removeUndefined?: boolean } = {},
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

  const SAFE_KEY_REGEX = /^[\w.-]{1,128}$/;
  for (const [key, value] of Object.entries(updates)) {
    if (POSTMESSAGE_FORBIDDEN_KEYS.has(key) || !isSafeKey(key)) continue;
    if (value === undefined && removeUndefined) {
      url.searchParams.delete(key);
    } else {
      url.searchParams.set(key, value === null ? "" : String(value));
    }
  }
  return url.href;
}

export function validateURL(
  urlString: string,
  options: {
    allowedOrigins?: string[];
    requireHTTPS?: boolean;
    maxLength?: number;
  } = {},
): { ok: true; url: URL } | { ok: false; error: Error } {
  const { allowedOrigins, requireHTTPS = false, maxLength = 2048 } = options;
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

  if (requireHTTPS && url.protocol !== "https:")
    return {
      ok: false,
      error: new InvalidParameterError("URL must use HTTPS."),
    };
  if (
    allowedOrigins &&
    allowedOrigins.length > 0 &&
    !allowedOrigins.includes(url.origin)
  )
    return {
      ok: false,
      error: new InvalidParameterError(
        `URL origin '${url.origin}' is not in allowlist.`,
      ),
    };

  return { ok: true, url };
}

export function parseURLParams(
  urlString: string,
  expectedParams?: Record<string, "string" | "number" | "boolean">,
): Record<string, string> {
  if (typeof urlString !== "string")
    throw new InvalidParameterError("URL must be a string.");
  let url: URL;
  try {
    url = new URL(urlString);
  } catch (error) {
    throw new InvalidParameterError(
      `Invalid URL: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const params: Record<string, string> = Object.create(null);
  const SAFE_KEY_REGEX = /^[\w.-]{1,128}$/;
  const paramMap = new Map<string, string>();

  for (const [key, value] of url.searchParams.entries()) {
    if (
      SAFE_KEY_REGEX.test(key) &&
      key !== "__proto__" &&
      key !== "constructor" &&
      key !== "prototype"
    ) {
      paramMap.set(key, value);
      Object.defineProperty(params, key, {
        value,
        configurable: true,
        enumerable: true,
        writable: false,
      });
    }
  }

  if (expectedParams) {
    for (const [expectedKey, expectedType] of Object.entries(expectedParams)) {
      const value = paramMap.get(expectedKey);
      if (value === undefined) {
        secureDevLog(
          "warn",
          "parseURLParams",
          `Expected parameter '${expectedKey}' is missing`,
          { url: urlString },
        );
        continue;
      }
      if (expectedType === "number" && isNaN(Number(value))) {
        secureDevLog(
          "warn",
          "parseURLParams",
          `Parameter '${expectedKey}' expected number, got '${value}'`,
          { url: urlString },
        );
      }
    }
  }
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
  try {
    return { ok: true, value: decodeURIComponent(_toStr(str)) };
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
