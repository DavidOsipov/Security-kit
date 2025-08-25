# URL Security Options

This document explains the new URL builder and validator options added to `src/url.ts` and the security rationale behind them. They were introduced to better align with the project's Security & Engineering Constitution (Zero Trust, Fail Loudly, Secure by Default).

## New API surface

- `createSecureURL(base, pathSegments?, queryParams?, fragment?, options?)`
  - options:
    - `requireHTTPS?: boolean` — if `true`, the resulting URL must use `https:` or the builder will throw an `InvalidParameterError`.
    - `maxLength?: number` — optional maximum allowed length for the resulting URL; exceeding it causes an `InvalidParameterError`.
    - `onUnsafeKey?: "throw" | "warn" | "skip"` — controls how the builder reacts when query keys are considered unsafe (for example `__proto__`, `constructor`, `prototype`, or keys disallowed by `POSTMESSAGE_FORBIDDEN_KEYS`). Defaults to `"throw"` (strict, fails loudly).

- `updateURLParams(baseUrl, updates, options?)`
  - options: same options as `createSecureURL` plus `removeUndefined?: boolean` (existing behavior).

- `validateURLStrict(urlString, options?)`
  - Convenience wrapper around `validateURL` which enforces HTTPS by default. Options: `{ allowedOrigins?: string[], maxLength?: number }`.

## Behavior details

- Unsafe query keys
  - Keys considered unsafe:
    - `__proto__`, `constructor`, `prototype`
    - Any key contained in `POSTMESSAGE_FORBIDDEN_KEYS` (project-wide constant used for secure postMessage interaction).
  - Detection is defensive:
    - The builder detects unsafe keys that are own properties (including non-enumerable own properties) and will act according to `onUnsafeKey`.
    - Special handling exists for `__proto__` because JavaScript object literals historically allow `"__proto__"` to affect an object's prototype; the builder rejects parameters where `__proto__` is present as an own property or where the params/updates object has a `null` prototype.

- Non-standard prototypes
  - If the params or updates objects have a non-standard prototype (not `Object.prototype` and not `null`) the builder logs or throws per `onUnsafeKey`, rejecting such objects by default.

- Fail loudly and secure-by-default
  - The default `onUnsafeKey` is `"throw"`, aligning with the constitution's "Fail Loudly, Fail Safely" principle. Callers that need more permissive behavior may opt into `"warn"` or `"skip"`.

## Rationale (Security Constitution mapping)

- Fail Loudly, Fail Safely (1.4): Security-relevant input errors throw rather than silently degrading.
- Principle of Least Privilege (1.3): Keys that could enable prototype pollution or collision are blocked.
- Verifiable Security (1.5): The behavior is test-covered and deterministic; CI runs include tests exercising these options.
- Build-time / Runtime Assertions (2.5 / 2.13): `validateURLStrict` and builder-level `requireHTTPS` provide additional runtime assertions that complement build-time checks.

## Migration notes

- Default `onUnsafeKey` was intentionally chosen to be strict (`throw`) to favor safety. If you currently rely on silently skipping keys, pass `onUnsafeKey: "skip"` or `"warn"` when calling the APIs.

## Examples

```ts
// Strict (default)
createSecureURL("https://example.test", ["path"], { a: 1 });

// Skip unsafe keys
createSecureURL("https://example.test", [], params, undefined, {
  onUnsafeKey: "skip",
});

// Enforce HTTPS and length
createSecureURL("https://example.test", [], { q: "value" }, undefined, {
  requireHTTPS: true,
  maxLength: 2048,
});

// Validate strictly
const res = validateURLStrict("https://example.test/");
if (!res.ok) throw res.error;
```

## Tests

Unit tests were added: `tests/unit/url.options.spec.ts` covering the new behaviors.

---

If you'd like this doc moved into a more formal RFC or added to README/API docs, I can do that next.
