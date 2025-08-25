# Security-Kit

![NPM Version](https://img.shields.io/npm/v/@david-osipov/security-kit?style=for-the-badge)
![License](https://img.shields.io/npm/l/@david-osipov/security-kit?style=for-the-badge)
![Build Status](https://img.shields.io/github/actions/workflow/status/david-osipov/Security-Kit/ci.yml?branch=main&style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)

**Security-Kit is not just a collection of utilities; it's a security philosophy you can install.**

This is a comprehensive, opinionated, and modern security toolkit for browser-based applications. It provides both cryptographic primitives and safe development helpers, designed to be the reference implementation for a project's Security Constitution. It is built on a **Zero Trust** philosophy, assuming no part of the system is infallible.

The entire library is written in TypeScript, has zero dependencies, and leverages the native **Web Crypto API** for maximum performance and security in modern environments.

## Core Philosophy

This library is built on a set of non-negotiable principles, codified in the [Security Constitution](./Security%20Consitution.md).

- 🛡️ **Secure by Default:** The default state of every function is the most secure state. Insecure actions are forbidden.
- 🏰 **Defense in Depth:** Multiple, independent security controls are layered to protect against failure in any single component.
- 🔒 **Principle of Least Privilege:** Every component operates with the minimum level of access necessary to perform its function.
- 💥 **Fail Loudly, Fail Safely:** In the face of an error or unavailable security primitive, the system throws a specific error and never silently falls back to an insecure alternative.
- ✅ **Verifiable Security:** A security control is considered non-existent until it is validated by an automated, adversarial test.

## Installation

```bash
npm install @david-osipov/security-kit
```

## Quick Start

The recommended way to initialize the library is to call an async function first, then seal the kit at your application's startup.

```typescript
import {
  SIMPLE_API,
  sealSecurityKit,
  isDevelopment,
} from "@david-osipov/security-kit";

async function initializeApp() {
  // 1. Call an async function first. This ensures the crypto API is ready.
  const secureId = await SIMPLE_API.generateSecureId(32);
  console.log("Generated an initial secure ID:", secureId);

  // 2. NOW, it is safe to seal the kit.
  // This prevents any further configuration changes, hardening your app against runtime tampering.
  sealSecurityKit();
  console.log("Security Kit is sealed.");

  // 3. Continue using the library.
  const uuid = await SIMPLE_API.generateSecureUUID();
  console.log("Secure UUID:", uuid);

  // Perform a timing-attack-resistant string comparison.
  // For security-critical comparisons (tokens, signatures), prefer the async
  // variant and require platform crypto to avoid falling back to a weaker path.
  const userInput = "user-provided-token";
  const secretToken = "a-very-secret-token-from-server";
  const areTokensEqual = await SIMPLE_API.secureCompareAsync(
    userInput,
    secretToken,
    { requireCrypto: true }, // fail loudly if SubtleCrypto is unavailable
  );

  console.log("Tokens are equal (timing-safe):", areTokensEqual);

  // Log a message that will only appear in development environments
  if (isDevelopment()) {
    console.log("This is a development build.");
  }
}

initializeApp();
```

## Key Features

- **Modern Cryptography:**
  - Cryptographically secure random number, integer, and byte generation.
  - High-performance, unbiased secure string generation (inspired by `nanoid`).
  - RFC 4122 v4 UUID generation.
  - Secure, non-extractable `CryptoKey` generation for AES-GCM.
  - Timing-attack resistant `secureCompare` and `secureCompareAsync` functions (prefer `secureCompareAsync(..., { requireCrypto: true })` for security-critical comparisons).
- **Secure Development Helpers:**
  - `secureDevLog`: A development-only logger with automatic redaction of sensitive data.
  - `secureWipe`: Best-effort memory wiping for sensitive buffers.
  - Hardened environment detection (`isDevelopment`, `isProduction`).
  - Rate-limited production error reporter.
- **URL & URI Hardening:**
  - `createSecureURL` and `updateURLParams`: Safely build and modify URLs without string interpolation vulnerabilities.
  - `validateURL` and `parseURLParams`: Robust validation and parsing of URL strings and their parameters.
  - RFC 3986 compliant component encoders (`encodeQueryValue`, `encodePathSegment`).
- **Cross-Context Communication:**
  - `sendSecurePostMessage` and `createSecurePostMessageListener` enforce strict origin validation, forbidding wildcards.
  - Hardened payload validation to prevent oversized payloads and prototype pollution.
- **Subresource Integrity (SRI):**
  - `generateSRI` to create integrity hashes for your assets.

## The Security Constitution

This library is more than just code; it's an architecture. The included [`Security Consitution.md`](./Security%20Consitution.md) is a mandatory read for any team using this library. It serves as a single source of truth for developers and security engineers, outlining the non-negotiable rules and principles that this library enforces.

## API Documentation

For a detailed understanding of every function, please refer to the JSDoc comments within the `index.ts` source file. Here are a few highlights of the advanced API:

#### `createSecureURL(base, pathSegments?, queryParams?, fragment?)`

Safely constructs a URL, preventing common encoding and path traversal vulnerabilities.

```typescript
import { createSecureURL } from "@david-osipov/security-kit";

const url = createSecureURL(
  "https://api.example.com",
  ["users", "search"],
  { q: "John Doe", filter: "active+premium" },
  "results",
);
// Returns: "https://api.example.com/users/search?q=John%20Doe&filter=active%2Bpremium#results"
```

## Publishing to npm

This repository includes a GitHub Actions workflow that publishes the package when a GitHub Release is published. To enable publishing:

- Add an `NPM_TOKEN` secret to the repository (Settings → Secrets → Actions) containing a token generated from your npm account.
- Create a Release (tag) in GitHub. The workflow `publish.yml` will run on release and publish the package.

Local pre-publish steps (the project runs these automatically via `npm run prepare`):

```bash
# Ensure version is bumped in package.json
npm run typecheck
npm run lint
npm test
npm run build
npm run generate:sbom
```

The `sbom.json` is included in the published package files.

#### `createSecurePostMessageListener(options)`

Listens for `postMessage` events while enforcing a strict origin allowlist and validating the payload.

```typescript
import { createSecurePostMessageListener } from "@david-osipov/security-kit";

const listener = createSecurePostMessageListener({
  allowedOrigins: ["https://trusted-partner.com"],
  onMessage: (data) => {
    console.log("Received trusted message:", data);
  },
  validate: {
    type: "string",
    payload: "object",
  },
});

// Don't forget to clean up!
// listener.destroy();
```

### Async secure string generation

For UI contexts where long synchronous CPU work could block the main thread, prefer the async, yielding generator:

```typescript
import { generateSecureStringAsync } from "@david-osipov/security-kit";

// Generate a 32-character ID using a small alphabet without blocking the UI
const controller = new AbortController();
const id = await generateSecureStringAsync(
  "abcdef0123456789",
  32,
  { signal: controller.signal }, // optional abort
);
```

Notes:

- `generateSecureStringAsync` mirrors the synchronous algorithm but yields between random-byte batches to keep the event loop responsive.
- It follows the same validation rules as the sync variant (alphabet size, uniqueness, and length bounds).
- It accepts an optional `AbortSignal` and will also abort automatically when `document.hidden` is `true` to preserve data integrity in background tabs (see Security Constitution §2.11).
- Use the async variant in performance-sensitive contexts (main thread, UI) and the synchronous one in short-lived background tasks or scripts where blocking is acceptable.

You can also pass an `AbortSignal` to `getSecureRandomInt(min, max, { signal })` — it will abort similarly and yield periodically during generation.

### URL validation: normalized origin allowlist

`validateURL(urlString, { allowedOrigins })` now normalizes origins with the URL standard (e.g., `https://example.com:443` equals `https://example.com`). Provide exact origins; wildcards are not allowed.

### postMessage: canonical origin format and payload freezing

- Origins used in `allowedOrigins` are canonicalized to `protocol//hostname[:port]` with default ports removed. Use the canonical form to avoid mismatches (trailing slashes and case differences are normalized).
- `createSecurePostMessageListener` deep-freezes sanitized payloads by default to ensure immutability. If your application requires high-throughput handling and you can prove immutability in consumers, set `freezePayload: false` to opt out.

### HTTPS-only policy for URL helpers

As a project-wide security policy, the URL helpers (`createSecureURL`, `updateURLParams`, `validateURL`) enforce HTTPS-only schemes by default. Consumers may pass an `allowedSchemes` option, but the library will only honor schemes that intersect with the internal SAFE_SCHEMES set (currently only `https:`). This prevents callers from accidentally enabling unsafe schemes like `javascript:` or `data:`.

```ts
import { validateURL } from "@david-osipov/security-kit";

const result = validateURL("https://example.com:443/path", {
  allowedOrigins: ["https://example.com"],
  requireHTTPS: true,
});

if (result.ok) {
  console.log(result.url.origin); // "https://example.com"
}
```

### Typed URL param parsing overload

`parseURLParams(url)` returns a frozen `Record<string, string>` with safe keys. When you know the expected params, use the typed overload for better DX:

```ts
import { parseURLParams } from "@david-osipov/security-kit";

const params = parseURLParams("https://example.com/?page=2&mode=compact", {
  page: "number",
  mode: "string",
} as const);
// params has type: Partial<Record<"page"|"mode", string>> & Record<string, string>
// Missing or type-mismatched keys are logged via secureDevLog warnings (dev only)
```

#### `secureDevLog(level, component, message, context?)`

A development-only logger that automatically redacts sensitive keys from context objects to prevent accidental secret leakage in console output.

```typescript
import { secureDevLog } from "@david-osipov/security-kit";

const sensitiveData = {
  userId: 123,
  token: "jwt-token-string-here",
  password: "user-password",
};

// In development, this will log the object with '[REDACTED]' values for token and password.
// In production, this function does nothing.
secureDevLog("info", "AuthComponent", "User logged in", sensitiveData);
```

## For Library Consumers & Test Environments

### Sanitization and DOM utilities

This library exposes a small, hardened sanitization API and a DOM validator utility:

- `Sanitizer` - a class that manages named DOMPurify configurations and (optionally) creates Trusted Types policies via `window.trustedTypes`. It accepts a DOMPurify instance in the constructor, which keeps the library environment-agnostic and testable.

- `STRICT_HTML_POLICY_CONFIG` - a conservative DOMPurify configuration that enables only basic HTML formatting and disables SVG/MathML. Use this as your default policy for general text content.

- `HARDENED_SVG_POLICY_CONFIG` - a hardened configuration for allowing sanitized SVG content while forbidding dangerous tags and attributes. Use only when you intentionally accept SVG input from trusted sources.

- `DOMValidator` and `defaultDOMValidator` - utilities that perform allowlist-based DOM querying and element validation. `DOMValidator` can be configured with a set of allowed root selectors; `defaultDOMValidator` is a convenience instance pre-configured for typical app layouts.

Example (browser):

```ts
import {
  Sanitizer,
  STRICT_HTML_POLICY_CONFIG,
} from "@david-osipov/security-kit";
import DOMPurify from "dompurify";

const dp = DOMPurify(window as any);
const sanitizer = new Sanitizer(dp, { strict: STRICT_HTML_POLICY_CONFIG });

// In browsers that support Trusted Types, createPolicy will register a TrustedHTML policy.
if (typeof window.trustedTypes !== "undefined") {
  sanitizer.createPolicy("my-app-strict");
}

// Fallback sanitization for non-TT environments
const safe = sanitizer.sanitizeForNonTTBrowsers(
  "<img src=x onerror=alert(1)>",
  "strict",
);
```

Example (tests / Node):

```ts
import createDOMPurify from "isomorphic-dompurify";
import {
  Sanitizer,
  STRICT_HTML_POLICY_CONFIG,
} from "@david-osipov/security-kit";

const DOMPurify = createDOMPurify(new (require("jsdom").JSDOM)().window);
const s = new Sanitizer(DOMPurify, { strict: STRICT_HTML_POLICY_CONFIG });
```

This library includes test-only code that is automatically removed from production builds using a global `__TEST__` flag. To leverage this Dead Code Elimination (DCE), you must configure your bundler.

**Example for Vite (`vite.config.ts`):**

```typescript
import { defineConfig } from "vite";

export default defineConfig({
  define: {
    // This makes the flag available in your code
    __TEST__: process.env.NODE_ENV === "test",
  },
});
```

This ensures that functions like `__test_resetCryptoStateForUnitTests` do not exist in your final production bundle.

## Production error reporting (optional)

This package exposes a rate-limited, centralized production error reporter which applications can configure or call directly. The reporter enforces token-bucket rate limiting, sanitizes errors for logging, and redacts sensitive context before forwarding to your handler.

Public API:

- `setProductionErrorHandler(fn | null)` — set a global handler that receives (error: Error, context: Record<string, unknown>). Pass `null` to disable.
- `configureErrorReporter({ burst, refillRatePerSec })` — tune the token-bucket parameters.
- `reportProdError(error, context?)` — manually emit an error to the configured handler (rate-limited). This is exported from the package root.

Example usage:

```ts
import {
  setProductionErrorHandler,
  configureErrorReporter,
  reportProdError,
} from "@david-osipov/security-kit";

// Configure the reporter on app startup
configureErrorReporter({ burst: 10, refillRatePerSec: 2 });
setProductionErrorHandler((err, ctx) => {
  // Forward to your telemetry pipeline (Sentry, Datadog, etc.)
  sendToTelemetry(err, ctx);
});

// When you need to report a critical issue:
try {
  riskyOperation();
} catch (err) {
  reportProdError(err instanceof Error ? err : new Error(String(err)), {
    module: "payment",
    operation: "chargeCustomer",
  });
}
```

Note: `reportProdError` will be a no-op if no production handler is configured or if the app is not running in a production environment (use `setAppEnvironment` to explicitly control environment detection during startup).

## Testing

This repository includes both fast unit tests and a small set of integration tests that exercise DOMPurify in a Node environment via `jsdom` + `isomorphic-dompurify`.

- Unit tests (fast): run with Vitest. These use lightweight mocks where appropriate and are intended to run in every CI job.
- Integration tests (jsdom + DOMPurify): run in the same Vitest job — we provide a global setup that initializes a shared JSDOM + DOMPurify instance for tests that need a realistic DOM.

Commands

```bash
# Run typecheck
npm run typecheck

# Run all tests (unit + integration)
npm test

# Run only unit tests (if you want to skip integrations you can use --testNamePattern)
npm test -- --testNamePattern "unit"
```

## Keyless signing (GitHub OIDC + sigstore)

This repository uses sigstore/cosign keyless signing in CI for SBOMs. That means the publish workflow signs SBOM artifacts (CycloneDX JSON, SPDX JSON) using GitHub OIDC assertions rather than a long-lived private key stored in secrets. Advantages:

- No long-lived private key in repository secrets.
- Signatures are tied to the release workflow invocation and issuer (GitHub Actions), improving provenance.

What you need to enable in the repository:

- Ensure the `publish` workflow has `id-token: write` and appropriate permissions (this repository already sets that in `.github/workflows/publish.yml`).
- Add an `NPM_TOKEN` secret so the workflow can publish to npm.

How the workflow signs and verifies SBOMs:

- The workflow uses `sigstore/cosign-installer` and `sigstore/cosign-action` to sign blobs using OIDC from GitHub Actions.
- The action produces detached signature files (`sbom.json.sig`, `sbom.spdx.json.sig`) and also fetches a signing certificate which can be uploaded as an artifact for auditing.

Verifying signatures locally (best-effort):

1. Install `cosign` locally (release binary or via Homebrew):

```bash
# macOS (Homebrew)
brew install sigstore/tap/cosign

# or download binary from https://github.com/sigstore/cosign/releases
```

2. Verify the SBOM signature and view the signing certificate:

```bash
cosign verify-blob --signature sbom.json.sig sbom.json
```

If the signature is valid, `cosign` will print verification results and the signing certificate information.

Notes and fallbacks:

- If you prefer to manage your own signing keys, the previous private-key flow using a base64 `COSIGN_KEY` secret is still possible; see the commit history for the earlier implementation. Keyless signing is recommended to minimize secret management overhead.
- For consumers who need to programmatically check signatures, consider publishing the signing certificate alongside SBOM artifacts or leveraging the Rekor transparency log which `cosign` uses by default.

### Example: Minimal keyless signing job

Below is a minimal example you can adopt for your own workflows that signs a single artifact using GitHub OIDC + `sigstore/cosign-action`:

```yaml
name: Sign SBOM
on:
  release:
    types: [published]

permissions:
  contents: read
  id-token: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        run: npm run generate:sbom
      - name: Install cosign helper
        uses: sigstore/cosign-installer@v2
      - name: Sign SBOM (keyless)
        uses: sigstore/cosign-action@v2
        with:
          args: sign-blob --signature sbom.json.sig sbom.json
      - name: Upload signature
        uses: softprops/action-gh-release@v1
        with:
          files: sbom.json.sig
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This example demonstrates a release-triggered signing job that uses GitHub OIDC (via `id-token: write`) to perform keyless signing.

Notes

- The test setup file `tests/setup/global-dompurify.ts` initializes a DOMPurify instance and exposes it to tests; the helper `tests/setup/domPurify.ts` is reusable for additional integration tests.
- `dompurify` is a peer dependency for this library (consumers should provide it). We use `isomorphic-dompurify` as a dev-time helper so integration tests can run in Node.
