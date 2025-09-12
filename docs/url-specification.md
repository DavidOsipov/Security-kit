# URL Module Specification (url.ts)

Version: 1.0.0
Last updated: 2025-08-25
Author: Security Kit (David Osipov)

## Purpose

This document is a rigorous, unambiguous specification for the `src/url.ts` module. It records the API contract, input/output shapes, error modes, security considerations, threat model, test coverage, and migration guidance. It's intended to be machine-readable by reviewers and auditable for CI-based security checks.

## Scope

Covers the public exports implemented in `src/url.ts` at the time of writing:

- createSecureURL
- updateURLParams
- validateURL
- validateURLStrict
- parseURLParams
- encode/encode\* helpers
- strictDecodeURIComponent helpers

## Design goals / principles

- Secure by Default: Defaults must prefer secure behavior (e.g., `onUnsafeKey: "throw"`).
- Fail Loudly, Fail Safely: When security-relevant input or environment assumptions aren't met, throw well-defined errors rather than silently degrade.
- Principle of Least Privilege: Avoid exposing or trusting keys that can cause prototype pollution or accidental collisions.
- Verifiable Security: Behaviors must be deterministic and covered by unit tests.
- Hardened Simplicity: Keep functions small, well-documented, and auditable.

## API Contracts

All function signatures and behaviors below are authoritative; code and tests must match these contracts.

createSecureURL(base, pathSegments?, queryParams?, fragment?, options?) -> string

- Inputs:
  - base: string — required; must be a valid URL string parseable by `new URL()`.
  - pathSegments: string[] — optional; each segment must be a non-empty string, length <= 1024, and must not decode to path separators or navigation tokens ("/", "\\", ".", "..").
  - queryParams: Record<string, unknown> — optional; plain object mapping keys to values. Keys may be any string but are subject to safety checks below. Values will be stringified.
  - fragment: string | undefined — optional; must be a string when provided.
  - options: {
    requireHTTPS?: boolean; // deprecated: library enforces HTTPS-only by default; present for backward compatibility
    maxLength?: number; // optional upper bound for resulting URL
    onUnsafeKey?: "throw" | "warn" | "skip"; // default: "throw"
    }
- Output:
  - Returns a string — the fully constructed URL (`url.href`).
- Error modes (throw InvalidParameterError):
  - base invalid or not a string
  - path segments malformed (decode error, traversal chars)
  - fragment not a string (when provided)
  - when `onUnsafeKey === 'throw'` and unsafe keys are detected (see Safety Rules)
  - when `requireHTTPS` is true and resulting URL is not https
  - when `maxLength` is provided and `url.href.length` exceeds it
- Notes:
  - Query parameters are appended using URLSearchParams to preserve existing params in `base`.
  - Keys that violate safety checks are handled according to `onUnsafeKey` (throw/warn/skip).
  - Scheme policy: This implementation enforces HTTPS-only by default. Callers may provide `allowedSchemes`, but the effective allowed schemes are the intersection of caller-provided schemes and the library-wide SAFE_SCHEMES set (currently only `https:`). This prevents callers from enabling unsafe schemes such as `javascript:` or `data:`.

updateURLParams(baseUrl, updates, options?) -> string

- Inputs:
  - baseUrl: string — required; must be parseable by `new URL()`.
  - updates: Record<string, unknown> — mapping of param names to new values; `undefined` values can be removed when `removeUndefined` is true (default true).
  - options: same as createSecureURL plus `removeUndefined?: boolean`.
- Output: updated URL string.
- Error modes: similar to createSecureURL (invalid base, unsafe keys per `onUnsafeKey`, `requireHTTPS`, `maxLength`).

validateURL(urlString, options?) -> { ok: true; url: URL } | { ok: false; error: Error }

- Inputs:
  - urlString: string
  - options: {
    allowedOrigins?: string[]; // optional origin allowlist; entries are normalized using URL().origin when possible
    requireHTTPS?: boolean; // default false
    maxLength?: number; // default 2048
    }
- Behavior:
  - If `urlString` is not a string, return ok=false with InvalidParameterError.
  - If `urlString.length > maxLength` return ok=false.
  - Attempt `new URL(urlString)`; on parse error return ok=false (InvalidParameterError).
  - If `requireHTTPS` is true and protocol != 'https:' return ok=false.
  - If `allowedOrigins` is provided and url.origin not in normalized allowlist, return ok=false.
  - Otherwise return { ok: true, url }.

validateURLStrict(urlString, options?) -> same shape as validateURL

- Shortcut wrapper that sets `requireHTTPS: true` and uses `maxLength` default of 2048.

parseURLParams(urlString, expectedParams?) -> readonly Record<string, string>

- Returns a null-prototype, frozen object where keys are safe keys only (see safety rules). Missing or type-mismatched expected params are logged via `secureDevLog`.

## Safety Rules / Key Handling

The module defends against prototype pollution and risky query keys.

1. Key allowlist regex

- `SAFE_KEY_REGEX = /^[\w.-]{1,128}$/` — keys must match this pattern to be considered safe for inclusion when reading from a URL.
- Keys that fail are not added to the `parseURLParams` return object.

2. Forbidden names

- Explicitly forbidden names: `__proto__`, `constructor`, `prototype`.
- Keys included in `POSTMESSAGE_FORBIDDEN_KEYS` are treated as forbidden when building or updating URLs.

3. Detection of unsafe keys on input objects

- Builders inspect the `queryParams` / `updates` object for dangerous keys. Detection strategy:
  - Build an ownKeyNames set including `Object.keys()`, `Object.getOwnPropertyNames()`, and `Reflect.ownKeys()`.
  - If `__proto__` is present as an own property or if the object's prototype is `null`, treat it as unsafe.
  - If any dangerous key is found in ownKeyNames, act according to `onUnsafeKey`.
  - Additionally, user-provided objects with non-standard prototypes (not `Object.prototype` and not `null`) are considered suspicious and cause a rejection or warning depending on `onUnsafeKey`.

4. onUnsafeKey behavior

- "throw": Immediately throw InvalidParameterError describing the issue.
- "warn": Call `secureDevLog('warn', ...)` and skip the offending keys.
- "skip": Silently skip the offending keys and continue.

## Threat Model

- Adversary goals considered:
  - Prototype pollution (e.g., injecting **proto** to change behavior on downstream consumers)
  - Query parameter injection that modifies app behavior or causes XSS when later used unsafely
  - URL tampering to bypass HTTPS requirements
- Assumptions:
  - Code executing these functions runs in a trusted JS environment (browser or Node) but must assume input objects can be attacker-controlled.
  - High-entropy secrets are not passed via these APIs.

## Error types and messages

- Errors are thrown as `InvalidParameterError` (defined elsewhere). Messages are explicit and suitable for logging. Example messages:
  - "Base URL must be a non-empty string."
  - "Path segments must be non-empty strings shorter than 1024 chars."
  - "Path segments must not contain separators or navigation."
  - "Resulting URL must use HTTPS."
  - "Resulting URL exceeds maxLength N."
  - "Unsafe query key 'X' present on params object."

## Testing

- Unit tests added: `tests/unit/url.options.spec.ts` (covers onUnsafeKey behaviours, requireHTTPS, maxLength, and validateURLStrict).
- Existing URL tests remain (url.create.spec.ts, url.params.spec.ts, url.normalize.spec.ts).
- CI must run `npm test` and ensure all tests pass.

## Examples and Usage

- Strict by default (fail loudly):

```ts
createSecureURL("https://example.test", ["path"], { a: 1 });
```

- Skip unsafe keys explicitly:

```ts
createSecureURL("https://example.test", [], params, undefined, {
  onUnsafeKey: "skip",
});
```

- Enforce HTTPS and length:

```ts
createSecureURL("https://example.test", [], { q: "value" }, undefined, {
  requireHTTPS: true,
  maxLength: 2048,
});
```

## Implementation notes & rationale

- We do not mutate input objects. The builders read `queryParams` / `updates` and use `URLSearchParams` to manage the URL's query string.
- We use multiple methods to enumerate own keys to detect non-enumerable properties and historically-problematic `__proto__` entries.
- We purposely err on the side of caution: objects with odd prototypes or with `__proto__` explicitly present will be rejected unless the caller explicitly opts for `onUnsafeKey: "skip"`.

### Hostname and IDNA Handling

The library enforces strict validation and encoding of hostnames to prevent homograph attacks and ensure consistent behavior across environments.

- Non-ASCII host labels must be converted to ASCII using an IDNA provider (punycode) via `encodeHostLabel`.
- Hostnames are lowercased and trailing dots are removed during normalization.
- Unicode inputs are normalized (NFKC) before processing.

Important API contract: `encodeHostLabel` requires a string input only. Passing non-string values (numbers, objects, functions, symbols, etc.) will throw an `InvalidParameterError`. This is intentional to preserve fail-closed semantics and avoid accidental coercions that could change the security meaning of a host label.

Notes:
- If you have a value that may not be a string, explicitly coerce it at the boundary you control (e.g., `String(value)`) and validate before calling `encodeHostLabel`.
- The IDNA provider must implement `toASCII(string): string`. Errors thrown by the provider are wrapped and rethrown as `InvalidParameterError`.

## Migration / Compatibility

- Default behavior is stricter than some legacy libraries that silently ignore unsafe keys. If your code depends on silent-skipping, update callers to pass `{ onUnsafeKey: "skip" }` or update to sanitize input objects before calling.

## Changelog

- 2025-08-25 v1.0.0 — Initial specification added and implemented in `src/url.ts`.

## Appendix: Tests (human-readable summary)

- `tests/unit/url.options.spec.ts`:
  - Ensures throwing behavior for `onUnsafeKey: 'throw'` when `__proto__` is an own property.
  - Ensures `onUnsafeKey: 'skip'` ignores unsafe key but keeps other keys.
  - Ensures `requireHTTPS` and `maxLength` enforcement in `createSecureURL`.
  - Ensures `updateURLParams` enforces `requireHTTPS` and `maxLength`.
  - Ensures `validateURLStrict` rejects HTTP.

---

If you want, I can:

- Export this document as part of a formal RFC in `docs/rfcs/` and open a PR.
- Add a one-line CHANGELOG entry and bump package version.
- Run `npm run typecheck` and `npm run lint` and fix any issues found.

Please tell me which follow-up you'd like next.
