Security Kit — URL helpers (README)

Target audience: junior front-end and back-end developers.
Purpose: quick reference + safe usage patterns + exact function signatures for `src/url.ts`.

## Package entry

This project is published as `@david-osipov/security-kit`. The public entry exports the library's APIs from `dist/index.mjs`/`dist/index.cjs` as configured in `package.json`.

E.g., in Node / ESM environments:

```js
import {
  createSecureURL,
  validateURL,
  normalizeOrigin,
} from "@david-osipov/security-kit";
```

In TypeScript (ESM):

```ts
import {
  createSecureURL,
  updateURLParams,
  validateURL,
  normalizeOrigin,
  parseURLParams,
  getUrlHardeningConfig,
  setUrlHardeningConfig,
  runWithStrictUrlHardening,
} from "@david-osipov/security-kit";
```

## Exact exported function signatures

(These are the runtime/TypeScript signatures taken verbatim from `src/url.ts`.)

- normalizeOrigin(o: string): string

- createSecureURL(
  base: string,
  pathSegments: readonly string[] = [],
  queryParameters: Record<string, unknown> | ReadonlyMap<string, unknown> = {},
  fragment?: string,
  options: {
  readonly requireHTTPS?: boolean;
  readonly allowedSchemes?: readonly string[]; // e.g. ["https:", "mailto:"]
  readonly maxLength?: number;
  readonly onUnsafeKey?: UnsafeKeyAction;
  readonly strictFragment?: boolean;
  readonly maxPathSegments?: number;
  readonly maxQueryParameters?: number;
  } = {},
  ): string

- updateURLParams(
  baseUrl: string,
  updates: Record<string, unknown> | ReadonlyMap<string, unknown>,
  options: {
  readonly removeUndefined?: boolean;
  readonly requireHTTPS?: boolean;
  readonly allowedSchemes?: readonly string[];
  readonly maxLength?: number;
  readonly onUnsafeKey?: UnsafeKeyAction;
  readonly maxQueryParameters?: number;
  } = {},
  ): string

- validateURL(
  urlString: string,
  options: {
  readonly allowedOrigins?: readonly string[];
  readonly requireHTTPS?: boolean;
  readonly allowedSchemes?: readonly string[];
  readonly maxLength?: number;
  readonly strictFragment?: boolean;
  readonly maxQueryParameters?: number;
  } = {},
  ): { readonly ok: true; readonly url: URL } | { readonly ok: false; readonly error: Error }

- validateURLStrict(
  urlString: string,
  options: {
  readonly allowedOrigins?: readonly string[];
  readonly maxLength?: number;
  } = {},
  ): { readonly ok: true; readonly url: URL } | { readonly ok: false; readonly error: Error }

- parseURLParams(urlString: string): Record<string, string>
- parseURLParams<K extends string>(
  urlString: string,
  expectedParameters: Record<K, ParameterType>,
  ): Partial<Record<K, string>> & Record<string, string>

- parseURLParams(urlString: string, expectedParameters?: Record<string, ParameterType>): Record<string, string>

- encodeComponentRFC3986(value: unknown): string
- encodePathSegment(value: unknown): string
- encodeQueryValue(value: unknown): string
- encodeMailtoValue(value: unknown): string
- encodeFormValue(value: unknown): string

- strictDecodeURIComponent(string\_: string): { ok: true; value: string } | { ok: false; error: Error }
- strictDecodeURIComponentOrThrow(string\_: string): string

- encodeHostLabel(label: string, idnaLibrary: { readonly toASCII: (s: string) => string }): string

## Configuration APIs (from `src/config.ts`)

- getUrlHardeningConfig(): UrlHardeningConfig
- setUrlHardeningConfig(cfg: Partial<UrlHardeningConfig>): void
- runWithStrictUrlHardening<T>(function\_: () => T): T

UrlHardeningConfig fields:

- enforceSpecialSchemeAuthority: boolean
- forbidForbiddenHostCodePoints: boolean
- strictIPv4AmbiguityChecks: boolean
- validatePathPercentEncoding: boolean

## Quick examples

1. Normalize & compare origins safely

```ts
import { normalizeOrigin } from "@david-osipov/security-kit";

const appOrigin = normalizeOrigin(
  process.env.APP_ORIGIN || "https://example.com",
);
const candidate = normalizeOrigin(userSuppliedUrl);
if (candidate !== appOrigin) throw new Error("Origin not allowed");
```

2. Create a safe URL for outbound requests

```ts
import { createSecureURL } from '@david-osipov/security-kit';

const safeUrl = createSecureURL('https://api.example.com', ['v1','users'], new Map([['q','joe']]), undefined, {
  requireHTTPS: true,
  allowedSchemes: ['https:'],
});
// safeUrl is a string you can pass to fetch
fetch(safeUrl).then(...)
```

3. Update query parameters safely

```ts
import { updateURLParams } from "@david-osipov/security-kit";

const updated = updateURLParams("https://example.com/search?q=foo", {
  q: "bar",
  page: 2,
});
```

4. Parse query params safely

```ts
import { parseURLParams } from "@david-osipov/security-kit";

const params = parseURLParams("https://example.com/?id=123");
// params is a frozen object with null prototype
```

5. Toggle strict IPv4 checks (startup)

```ts
import { setUrlHardeningConfig } from "@david-osipov/security-kit";

// Run at app startup
setUrlHardeningConfig({ strictIPv4AmbiguityChecks: true });
```

6. Scoped strictness in a short operation

```ts
import {
  runWithStrictUrlHardening,
  createSecureURL,
} from "@david-osipov/security-kit";

runWithStrictUrlHardening(() => {
  // This call will run with strict IPv4 checks regardless of environment
  createSecureURL("http://192.168.1"); // will be rejected in strict mode
});
```

## Security checklist (short)

- Prefer allow-lists for origins/hosts and schemes.
- Call `setUrlHardeningConfig` at startup, not at random times.
- Use `createSecureURL` for any untrusted input.
- Use `validateURL` for non-throwing checks.
- Avoid embedded credentials in URLs – the library rejects them.
- Keep strict defaults in production; use permissive dev defaults only for developer convenience.

## Troubleshooting

- If `normalizeOrigin` rejects `http://localhost:3000`, your environment may be running production defaults; in dev the library accepts an explicit localhost fallback. If you need it in production, explicitly add it to allowlist via `setUrlHardeningConfig` or `setRuntimePolicy` depending on scope.

## Notes & further work

- This README-style doc is generated from `src/url.ts`. If public API signatures change, update this doc accordingly.
- I can add small examples converted into runnable TypeScript files under `demo/` if you'd like.

---

If you'd like, I'll (A) add TypeScript-typed sample files under `demo/` demonstrating these examples, and (B) add a short index.md in `docs/User docs/` linking `url-readme.md` and the previous `url-module.md`.
