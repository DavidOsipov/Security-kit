// SPDX-License-Identifier: LGPL-3.0-or-later
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
// Use Node's built-in punycode for IDNA conversion when available.
// This keeps the project dependency-free for production while enabling
// deterministic hostname normalization in test and Node environments.
import { isForbiddenKey, getForbiddenKeys } from "./constants";
import {
  getSafeSchemes,
  getRuntimePolicy,
  getUrlHardeningConfig,
  getDangerousSchemes,
} from "./config";
import type { UrlHardeningConfig } from "./config";
import { environment } from "./environment";
import { secureDevLog as secureDevelopmentLog } from "./utils";

// This file contains deliberate, policy-driven branching that increases
// cognitive complexity. We allow the sonarjs cognitive-complexity rule to
// be disabled for this file with an explicit justification.
/* eslint-disable sonarjs/cognitive-complexity -- deliberate policy-heavy branching */

/* -------------------------
   Security hardening constants
   ------------------------- */

/**
 * Dangerous URL schemes that are permanently blocked for security.
 * Sourced from configuration to keep a single source of truth.
 */
const DANGEROUS_SCHEMES = new Set<string>(getDangerousSchemes());

/**
 * WHATWG "special" schemes (see https://url.spec.whatwg.org/#special-scheme)
 * These require an authority component and have distinct parsing rules.
 * We use this distinction to harden parsing behavior (rejecting ambiguous inputs).
 */
const SPECIAL_SCHEMES = new Set<string>([
  "http:",
  "https:",
  "ws:",
  "wss:",
  "ftp:",
  "file:",
]);

/**
 * WHATWG forbidden host code points, used to reject invalid authority characters.
 * Reference: https://url.spec.whatwg.org/#host-miscellaneous
 */
const FORBIDDEN_HOST_CODE_POINTS = new Set<string>([
  "\u0000",
  "\u0009",
  "\u000A",
  "\u000D",
  "\u0020",
  "#",
  "%",
  "/",
  ":",
  "?",
  "@",
  "[",
  "\\",
  "]",
  "^",
  "|",
]);

/**
 * Regex to detect Unicode Bidi control characters commonly used for display spoofing.
 * U+202A–U+202E (embedding/override), U+2066–U+2069 (isolates), U+200E/U+200F (marks),
 * U+061C (Arabic Letter Mark), U+00AD (Soft Hyphen).
 *
 * Security Constitution: Prevent visual spoofing in hostnames/authorities.
 * ASVS v5: Input validation and Unicode normalization.
 */
const BIDI_CONTROL_CHAR_REGEX =
  /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C\u00AD]/u;

/**
 * Hard limits to prevent denial-of-service during IDNA processing.
 * Applied before calling an IDNA provider.
 *
 * Note: These conservative defaults are local to URL handling to avoid
 * expanding global configuration surface. If a project-level configuration
 * emerges, these can be sourced from it.
 */
const MAX_AUTHORITY_CHARS_PRE_IDNA = 1024;
const MAX_HOST_LABELS_PRE_IDNA = 127;
const MAX_SINGLE_LABEL_CHARS_PRE_IDNA = 255;

/* -------------------------
   Utilities & helpers
   ------------------------- */

/**
 * Convert unknown to safe string. Collapses undefined (and previously null)
 * to empty string. Avoids using literal `null`.
 */
const _toString = (v: unknown): string => String(v ?? "");

/**
 * Normalize string input using NFKC to prevent Unicode normalization attacks.
 * NFKC (Normalization Form Compatibility Composition) provides the strictest
 * normalization, collapsing visually similar characters into common equivalents.
 *
 * OWASP ASVS v5 V5.1.4: Unicode normalization for input validation
 * Security Constitution: Fail Loudly - normalize to detect bypass attempts
 */
function normalizeInputString(input: unknown): string {
  return _toString(input).normalize("NFKC");
}

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

/**
 * Hostname validation and canonicalization utilities.
 *
 * Security rationale: WHATWG URL parsing is intentionally permissive. For
 * security-sensitive validation and normalization, we additionally enforce
 * RFC 1123 hostname label rules to prevent accepting invalid hostnames.
 *
 * OWASP ASVS v5 V1.2.2: Only safe URL protocols permitted and untrusted
 * data (including hostnames) must be validated/encoded according to context.
 *
 * Note: Non-host-based schemes (e.g., mailto:) have an empty hostname and
 * are not subject to hostname checks. IP literals are permitted and left
 * to the built-in URL parser for correctness.
 */
const MAX_FQDN_LENGTH = 253; // Excludes optional trailing dot

function canonicalizeHostname(hostname: string): string {
  // Lowercase and strip a single trailing dot to canonicalize FQDNs.
  const lower = String(hostname).toLowerCase();
  return lower.endsWith(".") ? lower.slice(0, -1) : lower;
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57; // 0-9
}

function isAlpha(code: number): boolean {
  return (
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) // a-z
  );
}

function isAlnum(code: number): boolean {
  return isDigit(code) || isAlpha(code);
}

function isHyphen(code: number): boolean {
  return code === 45; // '-'
}

function isAlnumHyphen(code: number): boolean {
  return isAlnum(code) || isHyphen(code);
}

function isValidHostLabelRFC1123(label: string): boolean {
  const labelLength = label.length;
  // Note: RFC 952 originally forbade single-character labels. Modern practice
  // (RFC 1123 and WHATWG URL Standard) permits them; we align with modern standards
  // and allow labels of length 1. This simplifies ergonomics without reducing security.
  if (labelLength < 1 || labelLength > 63) return false;
  const firstCode = label.charCodeAt(0);
  const lastCode = label.charCodeAt(labelLength - 1);
  if (!isAlnum(firstCode) || !isAlnum(lastCode)) return false;
  // UTS #46 hyphen restriction: a label must not contain hyphen-minus in both
  // the 3rd and 4th positions unless the label starts with the IDNA A-label
  // prefix "xn--" (which itself uses hyphens in those positions).
  if (
    labelLength > 3 &&
    label[2] === "-" &&
    label[3] === "-" &&
    label.slice(0, 4).toLowerCase() !== "xn--"
  ) {
    return false;
  }
  for (const ch of label) {
    const code = ch.charCodeAt(0);
    if (!isAlnumHyphen(code)) return false;
  }
  return true;
}

function parseIPv4Octet(s: string): number | undefined {
  if (s.length < 1 || s.length > 3) return undefined;
  if (![...s].every((ch) => isDigit(ch.charCodeAt(0)))) return undefined;
  const value = Number(s);
  return Number.isNaN(value) || value > 255 ? undefined : value;
}

function isLikelyIPv4(hostname: string): boolean {
  // Simple IPv4 dotted-quad check without regex; 0-255 per octet.
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => parseIPv4Octet(p) !== undefined);
}

function isLikelyIPv6(hostname: string): boolean {
  // WHATWG URL.hostname for IPv6 typically contains colons (no brackets).
  // We don't fully validate IPv6 here; rely on URL parser correctness.
  return hostname.includes(":");
}

function isValidHostnameRFC1123(hostnameRaw: string): boolean {
  if (hostnameRaw.length === 0) return false;
  const hostname = canonicalizeHostname(hostnameRaw);
  if (hostname.length === 0) return false;
  if (hostname.length > MAX_FQDN_LENGTH) return false;

  // Allow IP literals as-is; URL parsing ensures their correctness.
  if (isLikelyIPv4(hostname) || isLikelyIPv6(hostname)) return true;

  // Validate labels
  const labels = hostname.split(".");
  for (const label of labels) {
    if (!isValidHostLabelRFC1123(label)) return false;
  }
  return true;
}

function parseAndValidateURL(urlString: string, context: string): URL {
  return parseAndValidateURLInternal(urlString, context, false);
}

/**
 * Parse and validate a full URL (with paths allowed).
 * Use this for functions that need to accept complete URLs.
 */
export function parseAndValidateFullURL(
  urlString: string,
  context: string,
): URL {
  return parseAndValidateURLInternal(urlString, context, true);
}

function parseAndValidateURLInternal(
  urlString: string,
  context: string,
  allowPaths: boolean,
): URL {
  // Centralized policy-heavy checks; candidates for future small helper extraction.
  // Pre-validate the authority section from the raw input string to avoid
  // relying solely on WHATWG URL normalization, which is permissive and
  // may hide dangerous inputs (percent-encoding, raw unicode, embedded
  // credentials, or ambiguous IPv4 normalization).
  try {
    if (typeof urlString !== "string") {
      throw new InvalidParameterError(`${context}: URL must be a string.`);
    }
    // Read runtime toggles for URL hardening
    const urlHardening = getUrlHardeningConfig();

    // Enforce WHATWG special vs non-special scheme structure before further parsing.
    // Detect an initial scheme token `<scheme>:` ignoring leading spaces (which we reject later).
    const firstColon = urlString.indexOf(":");
    if (firstColon > 0) {
      const schemeSlice = urlString.slice(0, firstColon);
      const potentialScheme = canonicalizeScheme(schemeSlice);
      // The character(s) following the scheme
      const afterColon = urlString.slice(firstColon + 1, firstColon + 3);
      if (urlHardening.enforceSpecialSchemeAuthority) {
        if (SPECIAL_SCHEMES.has(potentialScheme)) {
          // Special schemes must be followed by "//" per hardened policy.
          if (afterColon !== "//") {
            throw new InvalidParameterError(
              `${context}: Special scheme '${potentialScheme}' must be followed by '//'`,
            );
          }
        } else if (afterColon === "//") {
          // Non-special schemes must not include an authority introducer.
          throw new InvalidParameterError(
            `${context}: Non-special scheme '${potentialScheme}' must not include an authority ('//').`,
          );
        }
      }
    }
    const schemeIndex = urlString.indexOf("://");
    // Declared here so the value is available later in the function scope.
    // eslint-disable-next-line functional/no-let -- complex logic requires mutable state
    let authorityForIPv4Check = "";
    // Allow a one-time rebuild of the input if IDNA Option B transforms the authority.
    // eslint-disable-next-line functional/no-let -- conditional rewrite requires let
    let effectiveUrlString = urlString;
    if (schemeIndex >= 0) {
      const authorityStart = schemeIndex + 3;
      // Find end of authority (first of '/', '?', '#')
      // eslint-disable-next-line functional/no-let -- complex loop logic requires mutable state
      let authorityEnd = urlString.length;
      for (const ch of ["/", "?", "#"]) {
        const index = urlString.indexOf(ch, authorityStart);
        if (index !== -1 && index < authorityEnd) authorityEnd = index;
      }
      const authorityRaw = urlString.slice(authorityStart, authorityEnd);

      if (authorityRaw.length === 0) {
        throw new InvalidParameterError(`${context}: Missing authority.`);
      }
      // Determine if a path follows the authority and enforce origin-only when required
      const hasPath =
        authorityEnd < urlString.length && urlString[authorityEnd] === "/";
      const isOnlyTrailingSlash =
        hasPath && authorityEnd + 1 === urlString.length;
      if (!allowPaths && hasPath && !isOnlyTrailingSlash) {
        throw new InvalidParameterError(
          `${context}: URL must not contain a path component.`,
        );
      }
      if (allowPaths && hasPath) {
        const rawPathAndAfter = urlString.slice(authorityEnd);
        const rawPathOnly = rawPathAndAfter.split(/[?#]/)[0] ?? "";
        preValidatePath(rawPathOnly, context, urlHardening, allowPaths);
      }
      const pre = preValidateAuthority(authorityRaw, context, urlHardening);
      // If IDNA Option B path executed, rebuild the URL string to include converted authority
      if (pre.changedByIdna) {
        const rebuilt =
          urlString.slice(0, authorityStart) +
          pre.effectiveAuthority +
          urlString.slice(authorityEnd);
        effectiveUrlString = rebuilt;
      }
      authorityForIPv4Check = pre.authorityForIPv4Check;
      const isBracketedIPv6 = pre.isBracketedIPv6;

      // Harden against ambiguous IPv4 syntaxes: reject shorthand (not 4 parts),
      // octal (leading zeros), and out-of-range octets for all-numeric dotted names.
      // Enforcement is controlled by runtime toggle for most contexts. We keep
      // normalizeOrigin strict regardless (origin parsing must be unambiguous).
      const enforceIPv4Ambiguity =
        !isBracketedIPv6 &&
        // Keep normalizeOrigin strict; validation obeys runtime toggle
        (context === "normalizeOrigin"
          ? true
          : urlHardening.strictIPv4AmbiguityChecks);
      {
        // IPv4 ambiguity and validity checks for all-numeric dotted names
        const hostForValidation = authorityForIPv4Check;
        const parts = hostForValidation.split(".");
        const allNumericDots =
          parts.length > 0 && parts.every((p) => /^\d+$/.test(p));
        if (allNumericDots) {
          // Always reject shorthand (not exactly 4 parts) regardless of toggle
          if (parts.length !== 4) {
            throw new InvalidParameterError(
              `${context}: Ambiguous IPv4-like host found. Use full 4-octet format.`,
            );
          }
          for (const part of parts) {
            if (part.length === 0) {
              throw new InvalidParameterError(
                `${context}: Invalid IPv4 address. Empty octet.`,
              );
            }
            const octetNumber = Number(part);
            if (
              Number.isNaN(octetNumber) ||
              octetNumber < 0 ||
              octetNumber > 255
            ) {
              throw new InvalidParameterError(
                `${context}: Invalid IPv4 address. Octet '${part}' is out of range.`,
              );
            }
            // Leading zeros: enforce only when strict ambiguity checks are enabled or required by context
            if (
              (context === "normalizeOrigin" ||
                (enforceIPv4Ambiguity &&
                  getUrlHardeningConfig().strictIPv4AmbiguityChecks)) &&
              part.length > 1 &&
              part.startsWith("0")
            ) {
              throw new InvalidParameterError(
                `${context}: Ambiguous IPv4-like host found. Leading zeros are not allowed.`,
              );
            }
          }
        }
      }
    }

    const url = new URL(effectiveUrlString);
    ensureNoCredentials(url, context);

    // For origin parsing context, require a valid hostname
    if (!allowPaths && (!url.hostname || url.hostname.length === 0)) {
      throw new InvalidParameterError(
        `${context}: URL must have a valid hostname for origin parsing.`,
      );
    }

    // Only validate hostname for host-based URLs
    if (url.hostname) {
      // Defense-in-depth: reject Bidi control characters in parsed hostname
      if (BIDI_CONTROL_CHAR_REGEX.test(url.hostname)) {
        throw new InvalidParameterError(
          `${context}: Hostname contains disallowed bidirectional control characters.`,
        );
      }
      const valid = isValidHostnameRFC1123(url.hostname);
      if (!valid) {
        throw new InvalidParameterError(
          `${context}: URL contains an invalid hostname.`,
        );
      }
      // Note: IPv4 shorthand preservation has been removed intentionally. Ambiguous
      // numeric dotted hosts are rejected during parsing to prevent SSRF/origin
      // confusion. We always return WHATWG-parsed hostnames after validation.
      // Canonicalize hostname on the returned URL object (lowercase and
      // remove a single trailing dot) so callers see a normalized form.
      try {
        // Canonicalize to lowercase and strip trailing dot
        const lower = canonicalizeHostname(url.hostname);
        // Optionally apply IDNA A-label conversion post-parse (defense-in-depth)
        const { enableIdnaToAscii, idnaProvider } = getUrlHardeningConfig();
        const canonical = (() => {
          if (enableIdnaToAscii && idnaProvider && lower.length > 0) {
            try {
              const converted = idnaProvider.toASCII(lower);
              // Validate that provider returned ASCII-only with no forbidden code points
              for (const ch of converted) {
                const code = ch.charCodeAt(0);
                if (code > 0x7f || FORBIDDEN_HOST_CODE_POINTS.has(ch)) {
                  throw new InvalidParameterError(
                    `${context}: IDNA provider returned invalid host.`,
                  );
                }
              }
              return converted;
            } catch (error: unknown) {
              throw new InvalidParameterError(
                makeSafeError(
                  `${context}: IDNA hostname conversion failed`,
                  error,
                ),
              );
            }
          }
          return lower;
        })();
        // Avoid mutating the URL object in place when possible; some linters
        // discourage in-place modification. Setting hostname here is an
        // intentional and small mutation to return a canonical value.
        if (canonical !== url.hostname) {
          /* eslint-disable-next-line functional/immutable-data -- deliberate small mutation to normalize return value */
          url.hostname = canonical;
        }
      } catch {
        // If canonicalization fails for any reason, return the URL as-is.
      }
    }

    // Validate that percent-encoded sequences in the pathname are well-formed
    // for any caller that allows paths. This catches malformed encodings early
    // in throwing APIs as well as validateURL. This check is also controllable
    // via runtime configuration to allow callers to opt-out in special cases.
    if (allowPaths && getUrlHardeningConfig().validatePathPercentEncoding) {
      const path = url.pathname;
      const malformedPercent = /%(?![0-9A-F]{2})/i;
      if (malformedPercent.test(path)) {
        throw new InvalidParameterError(
          `${context}: URL pathname contains malformed percent-encoding.`,
        );
      }
      // Also ensure decodeURIComponent would not throw
      try {
        decodeURIComponent(path);
      } catch {
        throw new InvalidParameterError(
          `${context}: URL pathname contains malformed percent-encoding.`,
        );
      }
    }
    return url;
  } catch (error: unknown) {
    if (error instanceof InvalidParameterError) throw error;
    throw new InvalidParameterError(
      makeSafeError(`Invalid base URL in ${context}`, error),
    );
  }
}

/* -------------------------
   Origin normalization
   ------------------------- */

/**
 * Normalize an origin string to canonical `protocol//host[:port]` form.
 * Rejects any non-root pathname, query, or fragment to ensure the input is a true origin.
 * Throws InvalidParameterError if the input cannot be parsed as an absolute origin.
 */
export function normalizeOrigin(o: string): string {
  // HARDENING: Apply NFKC normalization to prevent Unicode bypass attacks
  const normalizedOrigin = normalizeInputString(o);

  if (typeof normalizedOrigin !== "string" || normalizedOrigin.length === 0) {
    throw new InvalidParameterError("Origin must be a non-empty string.");
  }
  try {
    // Delegate to the same hardened parsing path that respects the configured
    // IDNA policy (Option A or B) to ensure consistent behavior across APIs.
    // NOTE: We intentionally do NOT implement a non-production fallback to
    // coerce raw Unicode authorities to punycode here. Raw non-ASCII in the
    // authority MUST be rejected unless an explicit IDNA provider is enabled
    // (Option B). This keeps behavior consistent and prevents accidental
    // accept-by-canonicalization in dev/test.
    const u = parseAndValidateURL(normalizedOrigin, "normalizeOrigin");
    // Reject inputs that include query or fragment to ensure callers pass
    // true origins only (protocol + host[:port]) as per strict policy.
    if (u.search && u.search.length > 0) {
      throw new InvalidParameterError(
        "Origin must not include a query component.",
      );
    }
    if (u.hash && u.hash.length > 0) {
      throw new InvalidParameterError(
        "Origin must not include a fragment component.",
      );
    }
    // Reject any non-root pathname. A valid origin must be exactly protocol//host[:port]
    // allowing at most a trailing slash as produced by the parser ("/").
    if (u.pathname && u.pathname !== "/" && u.pathname !== "") {
      throw new InvalidParameterError("Origin must not include a pathname.");
    }
    const proto = u.protocol; // includes trailing ':'
    const hostname = canonicalizeHostname(u.hostname);
    const port = u.port;
    const defaultPorts: Record<string, string> = {
      "http:": "80",
      "https:": "443",
    };
    const includePort = port !== "" && port !== defaultPorts[proto];
    const portPart = includePort ? `:${port}` : "";
    // Return canonical origin form WITHOUT trailing slash.
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
  if (Object.prototype.toString.call(x) !== "[object Object]") return false;
  // Enforce that the object's prototype is either Object.prototype or null
  // `Object.getPrototypeOf` is typed loosely; cast to `unknown` to avoid unsafe `any` assignment.
  const proto = Object.getPrototypeOf(x as object) as unknown;
  return proto === Object.prototype || proto === null;
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
// Complexity is intentional due to policy checks and explicit error paths.

export function getEffectiveSchemes(
  allowedSchemes?: readonly string[],
): ReadonlySet<string> {
  // Use an explicit arrow wrapper to avoid passing function reference directly
  // which some eslint rules flag (unicorn/no-array-callback-reference).
  const SAFE_SCHEMES = new Set(
    getSafeSchemes().map((c) => canonicalizeScheme(c)),
  );
  if (allowedSchemes === undefined) return SAFE_SCHEMES;
  if (Array.isArray(allowedSchemes) && allowedSchemes.length === 0)
    return new Set<string>(); // explicit deny-all

  // Same explicit wrapper for user-provided list.
  const userSet = new Set(
    Array.from(allowedSchemes).map((s) => canonicalizeScheme(s)),
  );
  const intersection = new Set([...userSet].filter((s) => SAFE_SCHEMES.has(s)));
  if (userSet.size > 0 && intersection.size === 0) {
    // Check runtime policy toggle to optionally allow permissive behavior.
    // `getRuntimePolicy()` is strongly typed; access the flag directly without `any` casts.
    const rp = getRuntimePolicy();
    if (rp.allowCallerSchemesOutsidePolicy === true) {
      return userSet;
    }
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
        if (onUnsafeKey === "warn" || onUnsafeKey === "skip") continue; // Allow processing to continue for warn and skip modes
        // This should never be reached, but kept for safety
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
      if (Object.hasOwn(object, "__proto__")) {
        const message = `Unsafe key '__proto__' present on ${componentName} object.`;
        if (onUnsafeKey === "throw") throw new InvalidParameterError(message);
        secureDevelopmentLog("warn", componentName, message, {
          base: baseReference,
        });
        if (onUnsafeKey === "warn" || onUnsafeKey === "skip") continue; // Allow processing to continue for warn and skip modes
        // This should never be reached, but kept for safety
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
      if (onUnsafeKey === "warn" || onUnsafeKey === "skip") continue; // Allow processing to continue for warn and skip modes
      // This should never be reached, but kept for safety
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

type ParameterType = "string" | "number" | "boolean";
type UnsafeKeyAction = "throw" | "warn" | "skip";

/**
 * Validates fragment for strict security mode.
 *
 * OWASP ASVS v5 V5.1.4: URL fragment validation
 * Prevents XSS and injection attacks through malicious fragments.
 */
function validateStrictFragment(fragment: string, context: string): void {
  // Check for dangerous schemes in fragment - common XSS vector
  for (const scheme of DANGEROUS_SCHEMES) {
    if (fragment.toLowerCase().includes(scheme)) {
      throw new InvalidParameterError(
        `Fragment contains dangerous scheme '${scheme}' in ${context}.`,
      );
    }
  }

  // Check for common XSS patterns in fragments
  const dangerousPatterns = [
    // eslint-disable-next-line sonarjs/code-eval -- security hardening: strings used for validation, not execution
    "javascript:",
    "data:",
    "vbscript:",
    "<script",
    "onerror=",
    "onload=",
    "eval(",
    "expression(",
  ];

  const lowerFragment = fragment.toLowerCase();
  for (const pattern of dangerousPatterns) {
    if (lowerFragment.includes(pattern)) {
      throw new InvalidParameterError(
        `Fragment contains potentially dangerous pattern '${pattern}' in ${context}.`,
      );
    }
  }
}

/**
 * Process query parameters for createSecureURL.
 * Uses Map or plain object; enforces safe keys and appends to url.searchParams.
 */
function processQueryParameters(
  searchParameters: URLSearchParams,
  parameters: Record<string, unknown> | ReadonlyMap<string, unknown>,
  onUnsafeKey: UnsafeKeyAction,
  base: string,
): void {
  _checkForDangerousKeys(parameters, onUnsafeKey, "createSecureURL", base);

  const entries: Iterable<readonly [string, unknown]> = _isMapLike(parameters)
    ? parameters.entries()
    : Object.entries(parameters);

  const hardening = getUrlHardeningConfig();
  const maxName = hardening.maxQueryParamNameLength ?? 128;
  const maxValue = hardening.maxQueryParamValueLength ?? 2048;

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
    if (key.length > maxName) {
      throw new InvalidParameterError(
        `Query parameter name exceeds maximum length (${maxName}).`,
      );
    }
    const stringValue = value === undefined ? "" : String(value ?? "");
    if (stringValue.length > maxValue) {
      throw new InvalidParameterError(
        `Query parameter value exceeds maximum length (${maxValue}).`,
      );
    }
    if (hasControlChars(stringValue)) {
      throw new InvalidParameterError(
        "Query parameter values must not contain control characters.",
      );
    }
    // Validate percent-encoding in query values to prevent mixed/malformed encodings.
    // Reject stray '%' not followed by two hex digits; also ensure decodeURIComponent wouldn't throw.
    if (/%(?![0-9A-F]{2})/i.test(stringValue)) {
      throw new InvalidParameterError(
        "Query parameter values contain malformed percent-encoding.",
      );
    }
    try {
      // Ensure value decodes without throwing; this does not change behavior, only validates.
      decodeURIComponent(stringValue);
    } catch {
      throw new InvalidParameterError(
        "Query parameter values contain malformed percent-encoding.",
      );
    }
    // Intentionally mutating URLSearchParams to append query parameters.
    searchParameters.append(key, stringValue);
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

  const hardening = getUrlHardeningConfig();
  const maxName = hardening.maxQueryParamNameLength ?? 128;
  const maxValue = hardening.maxQueryParamValueLength ?? 2048;

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
    if (key.length > maxName) {
      throw new InvalidParameterError(
        `Query parameter name exceeds maximum length (${maxName}).`,
      );
    }

    if (value === undefined && removeUndefined) {
      url.searchParams.delete(key);
      continue;
    }

    // Treat nullish as empty string for updates (preserving prior behavior); avoid null literal.
    const stringValue = String(value ?? "");
    if (stringValue.length > maxValue) {
      throw new InvalidParameterError(
        `Query parameter value exceeds maximum length (${maxValue}).`,
      );
    }
    if (hasControlChars(stringValue)) {
      throw new InvalidParameterError(
        "Query parameter values must not contain control characters.",
      );
    }
    // Enforce malformed percent-encoding parity with create path.
    if (/%(?![0-9A-F]{2})/i.test(stringValue)) {
      throw new InvalidParameterError(
        "Query parameter values contain malformed percent-encoding.",
      );
    }
    try {
      // Ensure decodes without throwing
      decodeURIComponent(stringValue);
    } catch {
      throw new InvalidParameterError(
        "Query parameter values contain malformed percent-encoding.",
      );
    }
    url.searchParams.set(key, stringValue);
  }
}

/* -------------------------
   Path segments & encoding
   ------------------------- */

const ENCODE_SUBDELIMS_RE = /[!'()*]/g;

function hasControlChars(s: string): boolean {
  for (const ch of s) {
    const code = ch.charCodeAt(0);
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
 * Rebuild a URL string from canonical components and parse it with the native URL parser.
 * This implements the immutable reconstruction step of the hardened pipeline.
 */
function _rebuildURL(components: {
  readonly protocol: string;
  readonly hostname: string;
  readonly port: string;
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
}): URL {
  const { protocol, hostname, port, pathname, search, hash } = components;
  const scheme = protocol.endsWith(":") ? protocol : `${protocol}:`;
  const portPart = port ? `:${port}` : "";
  const authority = `${hostname}${portPart}`;
  const rebuilt = `${scheme}//${authority}${pathname}${search}${hash}`;
  return new URL(rebuilt);
}

/**
 * Append path segments to URL. Validates decoded segment and appends encoded form.
 */
// appendPathSegments has been inlined into createSecureURL immutable construction.

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

/**
 * Lightweight pre-validation for bracketed IPv6 authority strings like "[::1]:8080".
 * Goals:
 * - Fail fast on obviously invalid forms (multiple ']' or missing closing bracket)
 * - Ensure content inside brackets is non-empty and only contains hex digits, ':' or '.'
 * - Validate optional port suffix (":" digits up to 5, 0-65535 checked later by URL)
 * - Avoid complex/backtracking regex to keep DoS risk minimal
 */
function preValidateBracketedIPv6Authority(
  authority: string,
  context: string,
): void {
  // Must start with '[' and contain exactly one closing ']'
  if (!authority.startsWith("[")) {
    throw new InvalidParameterError(`${context}: Invalid IPv6 authority.`);
  }
  const closeIndex = authority.indexOf("]");
  if (closeIndex === -1 || authority.indexOf("]", closeIndex + 1) !== -1) {
    throw new InvalidParameterError(
      `${context}: Invalid IPv6 authority brackets.`,
    );
  }
  const inside = authority.slice(1, closeIndex);
  if (inside.length === 0) {
    throw new InvalidParameterError(
      `${context}: IPv6 host inside brackets must not be empty.`,
    );
  }
  // Allow only hex digits, colon, and dot inside (to accommodate IPv4-embedded forms)
  for (const ch of inside) {
    const isHexDigit =
      (ch >= "0" && ch <= "9") ||
      (ch >= "a" && ch <= "f") ||
      (ch >= "A" && ch <= "F");
    if (!(isHexDigit || ch === ":" || ch === ".")) {
      throw new InvalidParameterError(
        `${context}: IPv6 host contains invalid character '${ch}'.`,
      );
    }
  }
  // After ']', allow optional ":<digits>" port
  const after = authority.slice(closeIndex + 1);
  if (after === "") return;
  if (!after.startsWith(":")) {
    throw new InvalidParameterError(
      `${context}: Invalid characters after IPv6 literal authority.`,
    );
  }
  const port = after.slice(1);
  if (port.length === 0 || port.length > 5) {
    throw new InvalidParameterError(
      `${context}: Invalid IPv6 port specification.`,
    );
  }
  for (const ch of port) {
    if (ch < "0" || ch > "9") {
      throw new InvalidParameterError(`${context}: IPv6 port must be numeric.`);
    }
  }
}

type PreValidatedAuthority = {
  readonly effectiveAuthority: string;
  readonly authorityForIPv4Check: string;
  readonly isBracketedIPv6: boolean;
  readonly changedByIdna: boolean;
};

/**
 * Pre-validate and optionally normalize the authority component prior to URL parsing.
 * Pure helper: operates on strings and config, throws InvalidParameterError on failure.
 */
function preValidateAuthority(
  authorityRaw: string,
  context: string,
  cfg: UrlHardeningConfig,
): PreValidatedAuthority {
  // Reject embedded credentials early (fail-fast)
  if (authorityRaw.includes("@")) {
    if (authorityRaw.indexOf("@") !== authorityRaw.lastIndexOf("@")) {
      throw new InvalidParameterError(
        `${context}: Authority contains multiple '@' characters (potential obfuscation).`,
      );
    }
    throw new InvalidParameterError(
      `${context}: URLs containing embedded credentials are not allowed.`,
    );
  }

  // Incidental whitespace policy: allow exactly one leading OR trailing space, not both.
  const authorityTrimmed = authorityRaw.trim();
  const normalizationChanged = authorityTrimmed !== authorityRaw;
  if (authorityTrimmed.length === 0) {
    throw new InvalidParameterError(`${context}: Missing authority.`);
  }
  if (authorityTrimmed !== authorityRaw) {
    const singleLeading = ` ${authorityTrimmed}`;
    const singleTrailing = `${authorityTrimmed} `;
    if (authorityRaw !== singleLeading && authorityRaw !== singleTrailing) {
      throw new InvalidParameterError(
        `${context}: Authority contains control characters or internal whitespace.`,
      );
    }
  }
  // Ensure no internal whitespace/control characters in trimmed value.
  // eslint-disable-next-line sonarjs/prefer-regexp-exec, no-control-regex, sonarjs/no-control-regex, sonarjs/duplicates-in-character-class -- security hardening: control character validation is intentional
  if (authorityTrimmed.match(/[\s\u0000-\u001f\u007f-\u009f]/)) {
    throw new InvalidParameterError(
      `${context}: Authority contains control characters or internal whitespace.`,
    );
  }

  const isBracketedIPv6 =
    authorityTrimmed.startsWith("[") && authorityTrimmed.includes("]");

  // Explicitly forbid '<' and '>' in authority
  if (authorityTrimmed.includes("<") || authorityTrimmed.includes(">")) {
    throw new InvalidParameterError(
      `${context}: Authority contains forbidden character '<' or '>'.`,
    );
  }

  // WHATWG forbidden host code points with context-aware exceptions
  if (cfg.forbidForbiddenHostCodePoints) {
    for (const ch of authorityTrimmed) {
      if (!FORBIDDEN_HOST_CODE_POINTS.has(ch)) continue;
      if (ch === ":") continue; // port validated below
      if (ch === "%") continue; // let dedicated percent-encoding check handle '%'
      if ((ch === "[" || ch === "]") && isBracketedIPv6) continue;
      throw new InvalidParameterError(
        `${context}: Authority contains forbidden character '${ch}'.`,
      );
    }
  }

  if (isBracketedIPv6) {
    preValidateBracketedIPv6Authority(authorityTrimmed, context);
  }

  // Validate colon usage for non-IPv6 authorities (host:port)
  if (!isBracketedIPv6 && authorityTrimmed.includes(":")) {
    const firstColon = authorityTrimmed.indexOf(":");
    const hasSecondColon = authorityTrimmed.indexOf(":", firstColon + 1) !== -1;
    const hostPart = authorityTrimmed.slice(0, firstColon);
    const portPart = authorityTrimmed.slice(firstColon + 1);
    const isAllDigits =
      portPart.length > 0 &&
      portPart.length <= 5 &&
      [...portPart].every((c) => c >= "0" && c <= "9");
    const validPortForm = hostPart.length > 0 && !hasSecondColon && isAllDigits;
    if (!validPortForm) {
      throw new InvalidParameterError(
        `${context}: Authority contains invalid colon usage.`,
      );
    }
  }

  // Reject control characters explicitly (defense-in-depth)
  for (const ch of authorityTrimmed) {
    const code = ch.charCodeAt(0);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
      throw new InvalidParameterError(
        `${context}: Authority contains control characters.`,
      );
    }
  }

  const idnaOutcome = (() => {
    // Default outcome with no changes
    const unchanged = {
      effectiveAuthority: authorityTrimmed,
      changedByIdna: normalizationChanged,
    } as const;
    // Non-ASCII handling: Option A (reject) vs Option B (convert)
    const containsNonASCII = [...authorityTrimmed].some(
      (ch) => ch.charCodeAt(0) > 127,
    );
    if (!containsNonASCII) return unchanged;
    if (BIDI_CONTROL_CHAR_REGEX.test(authorityTrimmed)) {
      throw new InvalidParameterError(
        `${context}: Authority contains disallowed bidirectional control characters.`,
      );
    }
    if (!cfg.enableIdnaToAscii) {
      throw new InvalidParameterError(
        `${context}: Raw non-ASCII characters in authority are not allowed (provide IDNA A-label).`,
      );
    }
    const provider = cfg.idnaProvider;
    if (!provider || typeof provider.toASCII !== "function") {
      throw new InvalidParameterError(
        `${context}: IDNA conversion enabled but idnaProvider.toASCII is not configured.`,
      );
    }
    // Pre-IDNA DoS caps
    if (authorityTrimmed.length > MAX_AUTHORITY_CHARS_PRE_IDNA) {
      throw new InvalidParameterError(
        `${context}: Authority length exceeds safe pre-IDNA maximum.`,
      );
    }
    const rawHostOnly = authorityTrimmed.replace(/:\d+$/, "");
    const rawLabels = rawHostOnly.split(".");
    if (rawLabels.length > MAX_HOST_LABELS_PRE_IDNA) {
      throw new InvalidParameterError(
        `${context}: Hostname contains too many labels.`,
      );
    }
    for (const rawLabel of rawLabels) {
      if (rawLabel.length === 0) {
        throw new InvalidParameterError(
          `${context}: Hostname contains an empty label.`,
        );
      }
      if (rawLabel.length > MAX_SINGLE_LABEL_CHARS_PRE_IDNA) {
        throw new InvalidParameterError(
          `${context}: Hostname label exceeds maximum length.`,
        );
      }
    }
    // Split host and port correctly
    const bracketed = isBracketedIPv6;
    const hostPort = (() => {
      if (bracketed) {
        const close = authorityTrimmed.indexOf("]");
        const h = authorityTrimmed.slice(0, close + 1);
        const p =
          authorityTrimmed[close + 1] === ":"
            ? authorityTrimmed.slice(close + 1)
            : "";
        return { h, p } as const;
      }
      const splitIndex = authorityTrimmed.lastIndexOf(":");
      if (splitIndex !== -1) {
        return {
          h: authorityTrimmed.slice(0, splitIndex),
          p: authorityTrimmed.slice(splitIndex),
        } as const;
      }
      return { h: authorityTrimmed, p: "" } as const;
    })();
    const hostPart = hostPort.h;
    const portPart = hostPort.p;
    const convertedHost = bracketed ? hostPart : provider.toASCII(hostPart);
    if (!bracketed) {
      for (const ch of convertedHost) {
        const code = ch.charCodeAt(0);
        if (code < 0x00 || code > 0x7f) {
          throw new InvalidParameterError(
            `${context}: IDNA provider returned non-ASCII host.`,
          );
        }
        if (FORBIDDEN_HOST_CODE_POINTS.has(ch)) {
          throw new InvalidParameterError(
            `${context}: IDNA provider returned host with forbidden characters.`,
          );
        }
      }
      const labels = convertedHost.split(".");
      if (convertedHost.length > MAX_FQDN_LENGTH) {
        throw new InvalidParameterError(
          `${context}: IDNA A-label exceeds maximum FQDN length.`,
        );
      }
      for (const label of labels) {
        if (!isValidHostLabelRFC1123(label)) {
          throw new InvalidParameterError(
            `${context}: IDNA A-label contains invalid label '${label}'.`,
          );
        }
      }
    }
    const rebuiltAuthority = convertedHost + portPart;
    return {
      effectiveAuthority: rebuiltAuthority,
      changedByIdna:
        normalizationChanged || rebuiltAuthority !== authorityTrimmed,
    } as const;
  })();

  const effectiveAuthority = idnaOutcome.effectiveAuthority;
  const changedByIdna = idnaOutcome.changedByIdna;
  // idnaOutcome encapsulates the non-ASCII handling path above.

  // Reject percent-encoding in authority
  if (authorityTrimmed.includes("%")) {
    throw new InvalidParameterError(
      `${context}: Percent-encoded sequences in authority are not allowed.`,
    );
  }

  const authorityForIPv4Check = authorityTrimmed.replace(/:\d+$/, "");
  return {
    effectiveAuthority,
    authorityForIPv4Check,
    isBracketedIPv6,
    changedByIdna,
  } as const;
}

/**
 * Pre-validate raw path substring for traversal sequences to prevent normalization bypass.
 */
function preValidatePath(
  rawPath: string,
  context: string,
  cfg: UrlHardeningConfig,
  allowPaths: boolean,
): void {
  if (!allowPaths) return;
  const traversalToken = /(?:^|[\\/])\.\.?(?:[\\/]|$)/.test(rawPath);
  const doubleSlash = /[\\/]{2,}/.test(rawPath);
  const hasTraversal = traversalToken || doubleSlash;
  if (!hasTraversal) return;
  const isValidationContext = context === "validateURL";
  const allowNormalizeInValidation =
    cfg.allowTraversalNormalizationInValidation;
  if (!(isValidationContext && allowNormalizeInValidation)) {
    throw new InvalidParameterError(
      `${context}: URL path contains traversal sequences.`,
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
    /** Enable strict fragment protection (blocks dangerous schemes in fragments). Defaults to true. */
    readonly strictFragment?: boolean;
    /** Maximum number of path segments to prevent DoS. Defaults to 64. */
    readonly maxPathSegments?: number;
    /** Maximum number of query parameters to prevent DoS. Defaults to 256. */
    readonly maxQueryParameters?: number;
  } = {},
): string {
  // HARDENING: Apply NFKC normalization to all string inputs first
  const normalizedBase = normalizeInputString(base);
  const normalizedPathSegments = pathSegments.map((segment) =>
    normalizeInputString(segment),
  );
  // Enforce fragment type strictly before normalization
  if (fragment !== undefined && typeof fragment !== "string") {
    throw new InvalidParameterError("Fragment must be a string.");
  }
  const normalizedFragment =
    fragment !== undefined ? normalizeInputString(fragment) : undefined;

  if (typeof normalizedBase !== "string" || normalizedBase.length === 0) {
    throw new InvalidParameterError("Base URL must be a non-empty string.");
  }

  try {
    const baseUrl = parseAndValidateFullURL(normalizedBase, "createSecureURL");

    const {
      allowedSchemes,
      maxLength: maxLengthOpt,
      onUnsafeKey = "throw",
      requireHTTPS = false,
      strictFragment = true,
      maxPathSegments = 64,
      maxQueryParameters = 256,
    } = options;

    // HARDENING: Resource limiting for DoS protection
    if (pathSegments.length > maxPathSegments) {
      throw new InvalidParameterError(
        `Path segments exceed maximum allowed (${maxPathSegments}).`,
      );
    }

    const parameterCount =
      queryParameters instanceof Map
        ? queryParameters.size
        : Object.keys(queryParameters).length;
    if (parameterCount > maxQueryParameters) {
      throw new InvalidParameterError(
        `Query parameters exceed maximum allowed (${maxQueryParameters}).`,
      );
    }

    // Scheme-aware construction: handle opaque (non-special) schemes safely
    const proto = canonicalizeScheme(baseUrl.protocol);
    const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
    if (!effectiveSchemes.has(proto)) {
      throw new InvalidParameterError(
        `Resulting URL scheme '${proto}' is not allowed.`,
      );
    }

    // Non-host (opaque) schemes: build with dedicated logic to avoid adding '//'
    if (!SPECIAL_SCHEMES.has(proto)) {
      // Permanent deny-list already enforced later, but guard early as well
      if (DANGEROUS_SCHEMES.has(proto)) {
        throw new InvalidParameterError(
          `The URL scheme '${proto}' is explicitly forbidden for security reasons.`,
        );
      }
      // Opaque scheme support: mailto:, tel:, sms:
      const opaque = buildOpaqueURL(
        baseUrl,
        proto,
        queryParameters,
        normalizedFragment,
        onUnsafeKey,
        maxQueryParameters,
      );
      if (typeof maxLengthOpt === "number" && opaque.length > maxLengthOpt) {
        throw new InvalidParameterError(
          `Resulting URL exceeds maxLength ${maxLengthOpt}.`,
        );
      }
      return opaque;
    }

    // IMMUTABLE PATH CONSTRUCTION
    const finalPathname = normalizedPathSegments.reduce(
      (currentPath, segment) => {
        if (
          typeof segment !== "string" ||
          segment.length === 0 ||
          segment.length > 1024
        ) {
          throw new InvalidParameterError(
            "Path segments must be non-empty strings shorter than 1024 chars.",
          );
        }
        // Validate on raw segment first to catch encoded navigation
        // sequences prior to any decoding.
        // Reject '%2e', '%2f', '%5c' (case-insensitive) in raw form.
        if (/%2e|%2f|%5c/i.test(segment)) {
          throw new InvalidParameterError(
            "Path segments must not contain encoded navigation.",
          );
        }
        const decoded = strictDecodeURIComponentOrThrow(segment);
        const triggersNavigation = (s: string): boolean => {
          if (s.includes("/") || s.includes("\\")) return true;
          if (s === "." || s === "..") return true;
          // Reject segments that resolve to only dots of length 3 as a conservative guard
          // against obfuscated parent/current directory traversal (e.g., '..%252e' -> '...').
          if (/^\.+$/.test(s) && s.length <= 3) return true;
          return false;
        };
        // Also guard against double-encoded traversal (e.g., '%252e' -> '%2e' -> '.')
        // Decode at most one additional time to detect hidden navigation.
        const secondDecoded = (() => {
          try {
            return decodeURIComponent(decoded);
          } catch {
            // ignore if further decoding fails; first decode already validated
            return decoded;
          }
        })();
        if (triggersNavigation(decoded) || triggersNavigation(secondDecoded)) {
          throw new InvalidParameterError(
            "Path segments must not contain separators or navigation.",
          );
        }
        const encoded = encodePathSegment(segment);
        const basePath = currentPath.endsWith("/")
          ? currentPath
          : currentPath + "/";
        return basePath + encoded;
      },
      baseUrl.pathname,
    );

    // Enforce max total path segments after construction to account for any existing
    // base pathname segments as well as newly appended segments.
    const totalSegments = finalPathname
      .split("/")
      .filter((s) => s.length > 0).length;
    if (totalSegments > maxPathSegments) {
      throw new InvalidParameterError(
        `Path segments exceed maximum allowed (${maxPathSegments}).`,
      );
    }

    // IMMUTABLE QUERY CONSTRUCTION
    const finalSearchParameters = new URLSearchParams(baseUrl.search);
    processQueryParameters(
      finalSearchParameters,
      queryParameters,
      onUnsafeKey,
      normalizedBase,
    );
    // Enforce final parameter count after merging with base URL params
    // to ensure DoS limits account for existing parameters.
    if (finalSearchParameters.size > maxQueryParameters) {
      throw new InvalidParameterError(
        `Final query parameters exceed maximum allowed (${maxQueryParameters}).`,
      );
    }

    // Determine effective fragment:
    // - If caller provides an explicit fragment, use it (after validation).
    // - Otherwise, preserve the base fragment only when we are not modifying structural
    //   components (no additional path segments and no added query parameters). This keeps
    //   createSecureURL idempotent for simple normalization while avoiding accidental
    //   propagation when constructing new URLs.
    const baseFragment = baseUrl.hash ? baseUrl.hash.slice(1) : undefined;
    const hasAddedPath = normalizedPathSegments.length > 0;
    const hasAddedQuery =
      (queryParameters instanceof Map
        ? queryParameters.size
        : Object.keys(queryParameters).length) > 0;
    // eslint-disable-next-line functional/no-let -- conditional derived value without nested ternaries improves clarity
    let effectiveFragment: string | undefined = normalizedFragment;
    if (effectiveFragment === undefined && !hasAddedPath && !hasAddedQuery) {
      effectiveFragment = baseFragment;
    }

    // HARDENING: Apply strict fragment validation in security mode
    if (effectiveFragment !== undefined) {
      if (hasControlChars(effectiveFragment))
        throw new InvalidParameterError(
          "Fragment contains control characters.",
        );
      if (strictFragment) {
        validateStrictFragment(effectiveFragment, "createSecureURL");
      }
    }

    // REBUILD FINAL URL IMMUTABLY
    const searchString = finalSearchParameters.toString();
    const fragmentHash = (() => {
      if (effectiveFragment === undefined) return "";
      const encoded = strictFragment
        ? encodeComponentRFC3986(effectiveFragment)
        : encodeURI(effectiveFragment);
      return `#${encoded}`;
    })();

    const finalUrl = _rebuildURL({
      protocol: baseUrl.protocol,
      hostname: baseUrl.hostname,
      port: baseUrl.port,
      pathname: finalPathname,
      search: searchString ? `?${searchString}` : "",
      // SECURITY: encode fragment after validation to ensure safe output
      hash: fragmentHash,
    });

    // Enforce requireHTTPS and scheme/length on the rebuilt URL
    if (requireHTTPS && canonicalizeScheme(finalUrl.protocol) !== "https:") {
      throw new InvalidParameterError(
        "HTTPS is required but URL scheme is not 'https:'.",
      );
    }
    enforceSchemeAndLength(finalUrl, allowedSchemes, maxLengthOpt);

    return finalUrl.href;
  } catch (error: unknown) {
    throw new InvalidParameterError(makeSafeError("Invalid base URL", error));
  }
}

/** Build safe opaque URLs for allowed non-host schemes. */
function buildOpaqueURL(
  baseUrl: URL,
  proto: string,
  queryParameters: Record<string, unknown> | ReadonlyMap<string, unknown>,
  normalizedFragment: string | undefined,
  onUnsafeKey: UnsafeKeyAction,
  maxQueryParameters: number,
): string {
  // Fragments on opaque schemes are generally meaningless; forbid to avoid confusion
  if (normalizedFragment !== undefined) {
    throw new InvalidParameterError(
      "Fragments are not allowed for opaque URL schemes.",
    );
  }

  const searchParameters = new URLSearchParams();
  processQueryParameters(
    searchParameters,
    queryParameters,
    onUnsafeKey,
    `${proto}opaque`,
  );
  if (searchParameters.size > maxQueryParameters) {
    throw new InvalidParameterError(
      `Final query parameters exceed maximum allowed (${maxQueryParameters}).`,
    );
  }

  switch (proto) {
    case "mailto:": {
      // Base path contains the address list (comma-separated) for non-special schemes
      const raw = baseUrl.pathname || "";
      const addresses = raw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      if (addresses.length === 0) {
        throw new InvalidParameterError(
          "mailto: requires at least one address",
        );
      }
      const encodedAddresses = addresses.map((addr) =>
        encodeMailtoAddress(addr),
      );
      const query = searchParameters.toString();
      const querySuffix = query ? `?${query}` : "";
      return `mailto:${encodedAddresses.join(",")}` + querySuffix;
    }
    case "tel:": {
      const raw = baseUrl.pathname || "";
      const normalized = normalizePhoneNumber(raw);
      const query = searchParameters.toString();
      const querySuffix = query ? `?${query}` : "";
      return `tel:${normalized}` + querySuffix;
    }
    case "sms:": {
      const raw = baseUrl.pathname || "";
      const normalized = normalizePhoneNumber(raw);
      const query = searchParameters.toString();
      const querySuffix = query ? `?${query}` : "";
      return `sms:${normalized}` + querySuffix;
    }
    default: {
      throw new InvalidParameterError(
        `Unsupported opaque scheme '${proto}' in createSecureURL`,
      );
    }
  }
}

function encodeMailtoAddress(address: string): string {
  // Conservative validation: local@domain with optional IDNA in domain.
  const parts = address.split("@");
  if (parts.length !== 2) {
    throw new InvalidParameterError("Invalid mailto address format");
  }
  const local = parts[0] ?? "";
  const domain = parts[1] ?? "";
  if (!local || !domain) {
    throw new InvalidParameterError("Invalid mailto address components");
  }
  // Validate domain via hostname canonical validator. This will throw on invalid.
  if (!isValidHostnameRFC1123(domain)) {
    throw new InvalidParameterError("Invalid mailto domain");
  }
  // Percent-encode conservatively (RFC 3986). '@' is not included in encoded output here as it's the separator
  const localEncoded = encodeMailtoValue(local);
  const domainEncoded = domain.toLowerCase();
  return `${localEncoded}@${domainEncoded}`;
}

function normalizePhoneNumber(raw: string): string {
  // Allow E.164-like numbers: optional leading '+', digits, spaces, hyphens, parentheses.
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new InvalidParameterError("Phone number must not be empty");
  }
  if (!/^[+\d()\-\s]+$/.test(trimmed)) {
    throw new InvalidParameterError("Phone number contains invalid characters");
  }
  // Strip spaces, hyphens, parentheses; keep a single leading '+' if present
  const leadingPlus = trimmed.startsWith("+");
  const digitsOnly = trimmed.replace(/[()\-\s]/g, "").replace(/^\+/, "");
  if (!/^\d{3,20}$/.test(digitsOnly)) {
    throw new InvalidParameterError("Phone number must contain 3-20 digits");
  }
  return (leadingPlus ? "+" : "") + digitsOnly;
}

/**
 * updateURLParams - update/patch the query part of an existing URL string.
 */
/* eslint-disable-next-line unicorn/prevent-abbreviations -- stable public API name; descriptive alias exported below */
export function updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown> | ReadonlyMap<string, unknown>,
  options: {
    readonly removeUndefined?: boolean;
    readonly requireHTTPS?: boolean;
    readonly allowedSchemes?: readonly string[];
    readonly maxLength?: number;
    readonly onUnsafeKey?: UnsafeKeyAction;
    /** Maximum number of query parameters to prevent DoS. Defaults to 256. */
    readonly maxQueryParameters?: number;
  } = {},
): string {
  // HARDENING: Apply NFKC normalization to base URL
  const normalizedBaseUrl = normalizeInputString(baseUrl);

  const { removeUndefined = true } = options;
  if (typeof normalizedBaseUrl !== "string")
    throw new InvalidParameterError("Base URL must be a string.");
  try {
    const url = parseAndValidateFullURL(normalizedBaseUrl, "updateURLParams");

    const {
      onUnsafeKey = "throw",
      requireHTTPS: requireHTTPSOpt = false,
      allowedSchemes,
      maxLength: maxLengthOpt,
      maxQueryParameters = 256,
    } = options;

    _checkForDangerousKeys(
      updates,
      onUnsafeKey,
      "updateURLParams",
      normalizedBaseUrl,
    );

    // HARDENING: Resource limiting for DoS protection
    const finalParameterCount =
      url.searchParams.size +
      (updates instanceof Map ? updates.size : Object.keys(updates).length);
    if (finalParameterCount > maxQueryParameters) {
      throw new InvalidParameterError(
        `Final query parameters would exceed maximum allowed (${maxQueryParameters}).`,
      );
    }

    processUpdateParameters(
      url,
      updates,
      removeUndefined,
      onUnsafeKey,
      normalizedBaseUrl,
    );

    // Enforce final parameter count after applying updates to account for
    // deletes/overwrites and prevent DoS via excessive parameters.
    if (url.searchParams.size > maxQueryParameters) {
      throw new InvalidParameterError(
        `Final query parameters exceed maximum allowed (${maxQueryParameters}).`,
      );
    }

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
  const arguments_ = {
    requireHTTPS: true,
    ...(options.allowedOrigins
      ? { allowedOrigins: options.allowedOrigins }
      : {}),
    ...(options.maxLength ? { maxLength: options.maxLength } : {}),
  } as const;
  return validateURL(
    urlString,
    arguments_ as unknown as {
      readonly allowedOrigins?: readonly string[];
      readonly requireHTTPS?: boolean;
      readonly allowedSchemes?: readonly string[];
      readonly maxLength?: number;
    },
  );
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
    /** Enable strict fragment protection (blocks dangerous schemes in fragments). Defaults to true. */
    readonly strictFragment?: boolean;
    /** Maximum number of query parameters to prevent DoS. Defaults to 256. */
    readonly maxQueryParameters?: number;
  } = {},
):
  | { readonly ok: true; readonly url: URL }
  | { readonly ok: false; readonly error: Error } {
  // HARDENING: Apply NFKC normalization to input URL
  const normalizedUrlString = normalizeInputString(urlString);

  const {
    allowedOrigins,
    allowedSchemes,
    maxLength = 2048,
    requireHTTPS = false,
    strictFragment = true,
    maxQueryParameters = 256,
  } = options;

  if (typeof normalizedUrlString !== "string") {
    return {
      ok: false,
      error: new InvalidParameterError("URL must be a string."),
    };
  }
  if (normalizedUrlString.length > maxLength) {
    return {
      ok: false,
      error: new InvalidParameterError(`URL length exceeds ${maxLength}.`),
    };
  }

  try {
    const url = parseAndValidateFullURL(normalizedUrlString, "validateURL");

    // Enforce permanent dangerous scheme block explicitly post-parse to ensure
    // consistency even if callers pass permissive allowedSchemes.
    const proto = canonicalizeScheme(url.protocol);
    if (DANGEROUS_SCHEMES.has(proto)) {
      return {
        ok: false,
        error: new InvalidParameterError(
          `URL scheme '${proto}' is explicitly forbidden for security reasons.`,
        ),
      } as const;
    }

    // Validate that percent-encoded sequences in the pathname are well-formed
    // to prevent ambiguous or malformed encodings from slipping through.
    if (getUrlHardeningConfig().validatePathPercentEncoding) {
      const path = url.pathname;
      // Validate percent-encoding using a regex: ensure every '%' is followed by two hex digits.
      // This is equivalent to scanning for malformed percent-encodings but avoids mutable loop counters.
      const malformedPercent = /%(?![0-9A-F]{2})/i;
      if (malformedPercent.test(path)) {
        return {
          ok: false,
          error: new InvalidParameterError(
            "URL pathname contains malformed percent-encoding.",
          ),
        };
      }
      // Also ensure decodeURIComponent would not throw to catch other malformations
      try {
        decodeURIComponent(path);
      } catch {
        return {
          ok: false,
          error: new InvalidParameterError(
            "URL pathname contains malformed percent-encoding.",
          ),
        };
      }
    }

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

    // HARDENING: Resource limiting for DoS protection
    if (url.searchParams.size > maxQueryParameters) {
      return {
        ok: false,
        error: new InvalidParameterError(
          `URL query parameters exceed maximum allowed (${maxQueryParameters}).`,
        ),
      };
    }

    // HARDENING: Validate fragment for security in strict mode
    if (strictFragment && url.hash && url.hash.length > 1) {
      try {
        // Remove leading '#' from hash for validation
        const fragmentContent = url.hash.slice(1);
        validateStrictFragment(fragmentContent, "validateURL");
      } catch (fragmentError: unknown) {
        return {
          ok: false,
          error:
            fragmentError instanceof Error
              ? fragmentError
              : new InvalidParameterError("Fragment validation failed."),
        };
      }
    }

    return { ok: true, url };
  } catch (error: unknown) {
    // Do not mask structural/parse errors with allowlist mismatch. If parsing fails,
    // return a generic malformed error regardless of allowlist parameters.
    return {
      ok: false,
      error: new InvalidParameterError(makeSafeError("Malformed URL", error)),
    } as const;
  }
}

/* -------------------------
   parseURLParams
   ------------------------- */

/* eslint-disable-next-line unicorn/prevent-abbreviations -- stable public API name; descriptive alias exported below */
export function parseURLParams(urlString: string): Record<string, string>;
export function parseURLParams<K extends string>(
  urlString: string,
  expectedParameters: Record<K, ParameterType>,
): Partial<Record<K, string>> & Record<string, string>;
export function parseURLParams(
  urlString: string,
  expectedParameters?: Record<string, ParameterType>,
): Record<string, string> {
  // HARDENING: Apply NFKC normalization to input URL
  const normalizedUrlString = normalizeInputString(urlString);

  if (typeof normalizedUrlString !== "string")
    throw new InvalidParameterError("URL must be a string.");

  const parseUrlOrThrow = (s: string): URL => {
    try {
      return parseAndValidateFullURL(s, "parseURLParams");
    } catch (error: unknown) {
      throw new InvalidParameterError(makeSafeError("Invalid URL", error));
    }
  };

  const url = parseUrlOrThrow(normalizedUrlString);

  // Build entries immutably from searchParams to avoid in-place array mutation.
  const parameterEntries: ReadonlyArray<readonly [string, string]> = Array.from(
    url.searchParams.entries(),
  ).filter(([key]) => isSafeKey(key));
  const parameterMap = new Map<string, string>(parameterEntries);

  // Validate expected parameters
  if (expectedParameters)
    _validateExpectedParameters(
      expectedParameters,
      normalizedUrlString,
      parameterMap,
    );

  // Freeze and return a POJO with a null prototype created from the map so
  // callers can assert the prototype is null to detect tampering.
  const object = Object.create(null) as Record<string, string>;
  // Intentionally creating a plain POJO from the Map for return; this requires
  // assigning properties on the newly-created object. It's safe and intentional.
  // eslint-disable-next-line functional/immutable-data -- creating return POJO from map
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
  const result = strictDecodeURIComponent(string_);
  if (!result.ok) throw result.error;
  return result.value;
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
  try {
    return idnaLibrary.toASCII(_toString(label));
  } catch (error: unknown) {
    throw new InvalidParameterError(
      `IDNA encoding failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
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
 * Uses defense-in-depth: first checks permanent blocklist, then whitelist.
 */
function enforceSchemeAndLength(
  url: URL,
  allowedSchemes?: readonly string[],
  maxLengthOpt?: number,
): void {
  const protocol = canonicalizeScheme(url.protocol);

  // HARDENING: First, check against the permanent blocklist (non-overridable)
  if (DANGEROUS_SCHEMES.has(protocol)) {
    throw new InvalidParameterError(
      `The URL scheme '${protocol}' is explicitly forbidden for security reasons.`,
    );
  }

  // Second, apply the configurable whitelist logic
  const effectiveSchemes = getEffectiveSchemes(allowedSchemes);
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

// Provide descriptive compatibility aliases for commonly-used public APIs.
export const updateURLParameters = updateURLParams;
export const parseURLParameters = parseURLParams;
