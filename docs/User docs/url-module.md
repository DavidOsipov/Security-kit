URL Module — secure usage guide

Audience: junior frontend/backend engineers. This guide explains how to use the project's secure URL helpers in `src/url.ts`, how the runtime configuration works, and how to adjust settings safely.

# Overview

This library provides hardened helpers for parsing, validating, normalizing, and building URLs safely. The helpers follow strict security rules (WHATWG-like canonicalization, forbid dangerous schemes, detect ambiguous IPv4 hosts, reject embedded credentials, validate percent-encoding) to prevent common web security mistakes: SSRF, open redirects, protocol confusion, and prototype pollution.

## Why this matters

URLs are deceptively tricky. Small mistakes lead to big security issues like:

- Server-Side Request Forgery (SSRF)
- Open Redirects (attackers craft URLs that redirect users to malicious sites)
- Credential leakage (username:password@host style URLs)
- Hostname confusion (IPv4 shorthand like `192.168.1` vs `192.168.1.1`)
- Prototype pollution from untrusted input used to build query objects

This module makes it safer to accept, parse and build URLs in your code.

## Files and exports

Key module: `src/url.ts`

Commonly used exported helpers (short summary):

- normalizeOrigin(input: string) -> string
  - Take an origin or URL-like string and return a canonical origin: `scheme://host(:port)`.
  - Throws typed errors when input is invalid or disallowed.

- createSecureURL(baseOrInput: string, opts?: { allowRelative?: boolean }) -> URL
  - Safe wrapper around the WHATWG URL constructor with extra checks: no credentials, allowed schemes, hostname validation, percent-encoding validation.

- validateURL(input: string) -> { ok: boolean, reason?: string }
  - Non-throwing validator for quick checks. Use when you don't want exceptions.

- updateURLParams(url: URL | string, params: Record<string, string | undefined>) -> URL
  - Safely set or delete query parameters without introducing unsafe characters or prototype-pollution risk. Accepts an object and updates a copy of the URL.

- parseURLParams(url: URL | string) -> Record<string, string>
  - Safely parse `search` into a plain object with null-proto conversion to prevent prototype pollution.

## Configuration (runtime)

Configuration lives in `src/config.ts` and exposes `getUrlHardeningConfig()` and `setUrlHardeningConfig()`.

Important options:

- strictIPv4AmbiguityChecks: boolean
  - When true, the library rejects ambiguous-looking IPv4 hosts like `192.168.1` and requires full 4-octet addresses like `192.168.1.1`.
  - This protects against accidental misrouting or parsing ambiguity.
  - Default behavior: strict in production (recommended), permissive in development/test for DX.

- validatePathPercentEncoding: boolean
  - When true, the module validates percent-encoding sequences in path and query components and rejects invalid or overlong encodings.

- allowedSchemes: string[]
  - Explicit allow-list for schemes. Dangerous schemes such as `javascript:`, `data:`, `file:`, `blob:` are blocked by default.

## How to change config safely

1. Read-only: use `getUrlHardeningConfig()` to inspect current behavior.

2. To change settings at runtime (e.g., in startup code):

```ts
import { setUrlHardeningConfig } from "./src/config";

setUrlHardeningConfig({
  strictIPv4AmbiguityChecks: true,
  validatePathPercentEncoding: true,
  allowedSchemes: ["https", "http"],
});
```

Important: configuration changes are global process-level state. Set them early during app startup. Avoid toggling them in the middle of request handling unless you understand the implications.

## Scoped strict mode

If you only need to run a specific operation with the strictest checks (for example when validating untrusted external input in a single function), use the helper `runWithStrictUrlHardening()` which temporarily enforces strict checks for the duration of the synchronous callback and restores prior settings afterwards.

Example:

```ts
import { runWithStrictUrlHardening } from "./src/config";
import { createSecureURL } from "./src/url";

runWithStrictUrlHardening(() => {
  const u = createSecureURL("http://192.168.1"); // will be rejected in strict mode
});
```

## Important usage patterns and examples

1. Accepting a user-supplied redirect URL (prevent open redirect)

Bad (do not do this):

```ts
// insecure — do not trust user input directly
res.redirect(req.query.next);
```

Good (use validation and normalization):

```ts
import { validateURL, normalizeOrigin } from "./src/url";

const candidate = req.query.next;
const { ok } = validateURL(candidate);
if (!ok) {
  // reject or use a fallback safe URL
  res.redirect("/");
  return;
}

// Ensure we only redirect to the same origin or a known allow-list
const origin = normalizeOrigin(candidate);
if (origin !== normalizeOrigin(process.env.APP_ORIGIN)) {
  // not allowed
  res.redirect("/");
  return;
}

res.redirect(candidate);
```

2. Building outbound requests from untrusted input (prevent SSRF)

- Whitelist hosts or origins where possible.
- Use `createSecureURL()` and assert scheme + hostname against your allow-list.

```ts
import { createSecureURL } from "./src/url";

function fetchFromUserUrl(input: string) {
  const url = createSecureURL(input);
  if (!["https"].includes(url.protocol.replace(":", "")))
    throw new Error("Only https allowed");
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error("Host not allowed");
  return fetch(url.toString());
}
```

3. Parsing query string into an object safely

Always convert parsed objects into null-prototype objects to avoid prototype pollution.

```ts
import { parseURLParams } from "./src/url";

const params = parseURLParams(req.url);
// params.__proto__ === null
```

## Security best practices and rationale

- Prefer allow-lists over deny-lists. Decide which hosts and schemes your application legitimately needs, and block everything else.
- Keep strict mode enabled in production. In dev/test you can be more permissive for convenience, but regularly run your tests with "production" configuration active to catch issues early.
- Reject credentials embedded in URLs. The library blocks `user:pass@host` style inputs because they leak secrets and confuse downstream HTTP libraries.
- Validate percent-encodings. Bad percent-encoding sequences can change how servers parse paths and query parts.
- Be explicit about IPv4: the library can require 4-octet IPv4 addresses to avoid ambiguity that attackers could exploit.
- Never use `eval`, never `JSON.parse` untrusted strings into runtime objects without sanitation; use the library helpers for parsing URLs and query strings.

## Troubleshooting

- "normalizeOrigin throws InvalidParameterError for http://localhost:3000" — this can happen if your app is running with strict production defaults. In development the library allows an explicit localhost fallback. If you're in production intentionally allow the origin via `setUrlHardeningConfig({ allowedOrigins: ['http://localhost:3000'] })` but prefer not to in real production.

- Tests failing complaining about IPv4 shorthand `192.168.1` — enable permissive mode in test/dev or use `runWithStrictUrlHardening` in tests where you want strict behavior. Prefer updating tests to provide fully-qualified addresses if they intend to test strict behavior.

- Performance issues during large batch URL operations — add early-exit checks (e.g., validate parameter counts) before performing heavy normalization; consider batching and throttling.

## Developer checklist

- Use `createSecureURL` for any untrusted input.
- Use `validateURL` when you want to check validity without throwing.
- Use `normalizeOrigin` when comparing origins.
- Use `parseURLParams`/`updateURLParams` to handle query parameters safely.
- Configure `UrlHardeningConfig` at application startup.
- Keep strict defaults in production.

## Migration & compatibility notes

- If you flip the global default to always-strict, some existing callers may start failing (especially if they pass shorthand IPv4 addresses or rely on permissive parsing). Provide migration notes in your changelog and bump major version if this introduces breaking changes.

- Prefer scoped `runWithStrictUrlHardening` in user-facing libraries that must maintain compatibility while providing an escape hatch for consumers who want strict behavior.

## Where to look in code

- Core logic: `src/url.ts`
- Runtime toggles: `src/config.ts` (`getUrlHardeningConfig`, `setUrlHardeningConfig`, `runWithStrictUrlHardening`).
- PostMessage helpers (origin normalization): `src/postMessage.ts` — relevant when you exchange URLs or origins across realms.

## Questions & help

If you're unsure which configuration to pick, ask a senior engineer and err on the side of stricter checks for production. If you want, I can prepare a checklist PR with example changes for an app to move from permissive to strict mode.

-- End of guide
