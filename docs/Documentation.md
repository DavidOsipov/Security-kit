# Security-kit Crypto Module — Documentation

This document records the security-sensitive behavior and public API of the `src/crypto.ts` module, including recent hardening changes (abort/visibility checks, dev logging centralization, and SRI recommendations). It is written to be machine- and human-readable and to serve as authoritative guidance for reviewers and implementers.

## Goals

- Document exact runtime contracts (inputs, outputs, thrown errors) for crypto APIs.
- Explain security rationale for abort/visibility checks and memory hygiene.
- Provide usage guidance for secure callers (how to handle sensitive inputs, how to cancel operations correctly).

---

## Table of Contents

- getSecureRandomAsync(options?)
- getSecureRandom()
- getSecureRandomBytesSync(length)
- getSecureRandomInt(min, max, options?)
- generateSecureStringSync(alphabet, size, options?)
- generateSecureStringAsync(alphabet, size, options?)
- generateSecureId / generateSecureIdSync
- generateSecureUUID
- createOneTimeCryptoKey(options?)
- createAesGcmNonce / createAesGcmKey128 / createAesGcmKey256
- generateSRI(input, algorithm?) — security notes
- Errors and behavior (Abort vs Hidden)
- Testing and maintenance notes

---

## Contract: getSecureRandomAsync(options?)

Signature:

- `getSecureRandomAsync(options?: { signal?: AbortSignal }): Promise<number>`

Inputs:

- `options.signal` (optional): an `AbortSignal`. If `signal.aborted` is true before or during the call, the call will abort.

Output:

- Resolves to a floating point number in `[0, 1)` sampled from a cryptographically secure RNG.

Errors:

- Throws/rejects when `options.signal.aborted` — an `AbortError`/`DOMException` is thrown when the environment supports `DOMException`, otherwise a generic `Error` with message `Operation aborted`.
- Throws/rejects with `RandomGenerationError` when the environment reports `document.hidden` (see Constitution §2.11) to avoid collecting data in throttled or background contexts.
- Throws `CryptoUnavailableError` if the Web Crypto APIs are not available.

Security rationale:

- Accepting an optional `AbortSignal` allows callers to cancel long-running or user-aborted operations. It also makes cancellation semantics consistent between async and sync APIs.
- Checking `document.hidden` prevents background collection or corrupt timing measurements in throttled tabs (Constitution §2.11).

Usage example:

```js
const controller = new AbortController();
setTimeout(() => controller.abort(), 2000);
try {
  const v = await getSecureRandomAsync({ signal: controller.signal });
  // use v
} catch (err) {
  // handle abort/visibility/crypto errors
}
```

---

## Contract: generateSecureStringSync(alphabet, size, options?)

Signature:

- `generateSecureStringSync(alphabet: string, size: number, options?: { signal?: AbortSignal }): string`

Inputs:

- `alphabet`: allowlisted characters (unique characters only).
- `size`: integer length of requested string (validated: 1..1024).
- `options.signal` (optional): If `signal.aborted` or `document.hidden` the operation will throw.

Output:

- A secure string sampled without modulo bias using rejection sampling.

Errors:

- Throws `InvalidParameterError` on invalid alphabet/size inputs.
- Throws `RandomGenerationError` when aborted due to `document.hidden`.
- Throws `DOMException` / `Error` on `AbortSignal` abort event (see getSecureRandomAsync behavior above).

Security rationale:

- Synchronous code paths are kept auditable and bounded (iteration caps). Because `getRandomValues` is synchronous, we still enforce `document.hidden` checks to comply with Constitution §2.11 in case this function is used in timing/measurement-sensitive contexts.

---

## Contract: generateSRI(input, algorithm?)

Signature:

- `generateSRI(input: string | ArrayBuffer, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha384'): Promise<string>`

Inputs:

- `input`: content to hash for SRI. Prefer `ArrayBuffer` / `Uint8Array` for sensitive content.

Output:

- Returns SRI string in the format `"shaXXX-<base64>"`.

Security note (important):

- @security-note: For sensitive inputs prefer passing `ArrayBuffer`/`Uint8Array` instead of `string`. JavaScript string objects are immutable and engines may retain copies that cannot be securely wiped; by passing binary buffers callers can call `secureWipe()` on those buffers after use.

Errors:

- Throws `CryptoUnavailableError` if `SubtleCrypto.digest` is not available.

---

## Centralized dev logging

- All development-only logs should use `secureDevLog(level, component, message, context?)` which performs redaction and dispatches a `secure-dev-log` CustomEvent in browsers. This change replaces ad-hoc `console.warn` usage in crypto code to make linting and CI checks straightforward and to satisfy Constitution guidance about dev-only console wrapping.

---

## Errors & types

- `CryptoUnavailableError` — thrown when required Web Crypto APIs are missing.
- `RandomGenerationError` — used when a generation fails due to environment restrictions (e.g., `document.hidden`) or iteration caps.
- `InvalidParameterError` — thrown on invalid inputs.
- `AbortError` / `DOMException` / generic `Error` — thrown when `AbortSignal` is triggered; exact instance depends on environment support.

Notes for callers:

- Treat all thrown errors as recoverable: if randomness generation fails, prefer failing loudly and preventing use of degraded randomness sources.
- Use `try { await getSecureRandomAsync({ signal }) } catch (err) { /* handle */ }` and do not fall back to `Math.random()`.

## Timing-safe comparisons

- Prefer `secureCompareAsync(a, b, { requireCrypto: true })` for security-critical string comparisons (tokens, signatures). When `requireCrypto` is set, the call will throw a `CryptoUnavailableError` if the platform SubtleCrypto is not available, enforcing the Constitution's "Fail Loudly" requirement instead of silently falling back to a weaker sync path.

Usage example:

```js
try {
  const equal = await secureCompareAsync(userToken, serverToken, {
    requireCrypto: true,
  });
  if (equal) {
    /* proceed */
  }
} catch (err) {
  // handle missing crypto or other errors explicitly
}
```

---

## Testing & maintenance notes

- Unit tests exist under `tests/unit` covering abort and hidden-document behavior:
  - `crypto.signal.spec.ts` — confirms abort semantics for sync and async generators.
  - `crypto.async-hidden.spec.ts` — confirms `getSecureRandomAsync` rejects when `document.hidden`.
  - `crypto.sync-hidden.spec.ts` — confirms `generateSecureStringSync` throws when `document.hidden`.
- Tests mock `document.hidden` using `vi.spyOn(document, 'hidden', 'get')` because in some test runtimes the property is a readonly getter.

---

## Change log (recent)

- Added optional `options?: { signal?: AbortSignal }` to `getSecureRandomAsync` and `generateSecureStringSync` to standardize abort semantics.
- Enforced `document.hidden` checks in both sync and async crypto APIs to comply with Constitution §2.11.
- Replaced direct `console.warn` in `createOneTimeCryptoKey` with `secureDevLog` for consistent dev-only logging.
- Added `@security-note` to SRI generation recommending ArrayBuffer inputs.
- Added unit tests to assert abort/hidden behavior.

---

## Contract: Secure postMessage utilities

This module provides hardened helpers for cross-context messaging using the browser `postMessage` API. The implementation enforces strict origin allowlists, positive validation of incoming payloads, defenses against prototype pollution, and privacy-preserving diagnostics.

API surface

- `sendSecurePostMessage(options: { targetWindow: Window; payload: unknown; targetOrigin: string })`
  - Sends a JSON-serializable payload to `targetWindow` at `targetOrigin`.
  - `targetOrigin` must be an absolute origin (recommended `https:`). `localhost`/`127.0.0.1` are allowed for development, but other non-HTTPS origins are rejected.
  - The payload is JSON.stringified and size-limited to `POSTMESSAGE_MAX_PAYLOAD_BYTES`.

- `createSecurePostMessageListener(opts | allowedOrigins, onMessage?)` — creates a listener bound to an allowlist.
  - Two calling forms supported:
    - `createSecurePostMessageListener(['https://a.example'], onMessage)` (legacy)
    - `createSecurePostMessageListener({ allowedOrigins: [...], onMessage, validate, allowExtraProps, expectedSource, allowOpaqueOrigin, enableDiagnostics })`

Listener options (recommended usage):

- `allowedOrigins: string[]` (required) — array of absolute origins to accept. Origins must be `https:` (or `http:` for `localhost`).
- `onMessage: (data: unknown) => void` (required) — callback invoked with the sanitized, null-prototype, deep-frozen payload.
- `validate: ((d: unknown) => boolean) | Record<string, 'string'|'number'|'boolean'|'object'|'array'>` (strongly recommended) — positive validator or schema. If a schema is provided, each listed property must be present and match type. By default, extra properties are rejected unless `allowExtraProps: true`.
- `allowExtraProps?: boolean` (default: `false`) — relax extra-property rejection when using a schema.
- `expectedSource?: Window | MessagePort` — optional stronger binding that ensures `event.source === expectedSource` before accepting messages.
- `allowOpaqueOrigin?: boolean` (default: `false`) — whether to accept messages with `event.origin === 'null'`. This is discouraged and should be used only where necessary and documented.
- `enableDiagnostics?: boolean` (default: `false`) — when true, captured validation failures may include a salted fingerprint to help debugging. Fingerprints are salted per-process and rate-limited.

Security characteristics

- Prototype pollution: incoming objects are converted to null-prototype objects and forbidden keys (`__proto__`, `constructor`, `prototype`) are removed.
- Immutability: the sanitized payload is deep-frozen before delivery to `onMessage` to avoid accidental mutation and to enforce least-privilege usage.
- Diagnostics & privacy: fingerprints included in diagnostics are salted with a per-process RNG and are rate-limited (small budget) to avoid DoS and prevent linkability across process restarts. Diagnostics (and fingerprint inclusion) are opt-in via `enableDiagnostics` and should remain disabled in production.

Usage recommendations

- Always provide a `validate` function or schema for any listener that performs security-sensitive actions. Prefer schema-based validators with `allowExtraProps: false`.
- Bind listeners to a specific `expectedSource` when you have a direct `Window` reference (defense in depth).
- Keep `enableDiagnostics` off in production. If you enable it for debugging, ensure logs with fingerprints are handled per your privacy policy.

---

If you need this document converted into a stricter machine-readable format (JSON Schema or markdown front-matter with types), tell me which format you prefer and I will generate it.

## Note: build required for worker-based isolation tests

Some tests under `tests/security/` use a worker that imports the compiled ESM entrypoint (`dist/index.mjs`) to get a fresh module realm. Because those tests import compiled artifacts, you must build the project before running them:

- Locally: run `npm run build` (this runs `tsup` and writes `dist/index.mjs`).
- CI: ensure your pipeline runs the project's build step before running tests (for example, `npm ci && npm run build && npm test`).

Failing to build first will cause runtime errors in the worker such as "Cannot find module ... imported from ..." or "Must use import to load ES Module", because the worker cannot import TypeScript sources directly in a separate Node ESM realm.

Using the compiled `dist` artifacts for worker-based isolation tests keeps the test environment close to what runs in production and avoids ESM/loader mismatches.
