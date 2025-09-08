# Security-Kit

![NPM Version](https://img.shields.io/npm/v/@david-osipov/security-kit?style=for-the-badge)
![License](https://img.shields.io/npm/l/@david-osipov/security-kit?style=for-the-badge)
![Build Status](https://img.shields.io/github/actions/workflow/status/david-osipov/Security-Kit/ci.yml?branch=main&style=for-the-badge)
![Security Tests](https://img.shields.io/github/actions/workflow/status/david-osipov/Security-Kit/ci.yml?branch=main&style=for-the-badge&label=security-tests)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)

![Security-kit logo](https://github.com/user-attachments/assets/4fde77c1-9510-4b55-8e19-83f7be42201a)


# ⚠️ SECURITY WARNING: EXPERIMENTAL & NON-AUDITED ⚠️

## **DO NOT USE THIS LIBRARY IN PRODUCTION ENVIRONMENTS.**

This repository is a security-critical library created as a case study in using advanced prompt engineering with Large Language Models (LLMs) to generate code aligned with the OWASP Application Security Verification Standard (ASVS).

**This code has NOT undergone a professional, third-party security audit.**

**Security-Kit is not just a collection of utilities; it's a security philosophy you can install.**

This is a comprehensive, opinionated, and modern security toolkit for browser-based applications. It provides both cryptographic primitives and safe development helpers, all designed to be the reference implementation for a project's Security Constitution. It is built on a **Zero Trust** philosophy, assuming no part of the system is infallible.

The entire library is written in TypeScript, has zero production dependencies, and leverages the native **Web Crypto API** for maximum performance and security in modern environments.

---

## Secret length policy

Security-kit enforces a minimum secret length for HMAC-based API signing and
verification. This protects users from weak keys and accidental downgrade to
insufficient entropy. The library normalizes secrets to bytes and validates
their length before use.

- Minimum accepted length: 32 bytes (256 bits) is recommended for production.
- Tests and examples in this repository have been upgraded to use 32-byte
  secrets.

Migration guidance:

- If you use shorter secrets, rotate to a 32-byte key as soon as possible.
- For existing systems where rotation is non-trivial, consider wrapping the
  existing key with a KDF (e.g., HKDF-SHA256) that derives a 32-byte symmetric
  key from your existing secret, and then adopt the derived key for signing.

Preventing regressions:

- This repository includes tests that validate the minimum secret length. We
  recommend adding a CI check (or an eslint rule) that scans for short literal
  secrets in test code to avoid accidental reintroduction of weak test keys.

## Table of Contents

- [Security-Kit](#security-kit)
- [⚠️ SECURITY WARNING: EXPERIMENTAL \& NON-AUDITED ⚠️](#️-security-warning-experimental--non-audited-️)
  - [**DO NOT USE THIS LIBRARY IN PRODUCTION ENVIRONMENTS.**](#do-not-use-this-library-in-production-environments)
  - [Secret length policy](#secret-length-policy)
  - [Table of Contents](#table-of-contents)
  - [Core Philosophy](#core-philosophy)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Choosing the right API (security vs convenience)](#choosing-the-right-api-security-vs-convenience)
  - [Supported runtimes](#supported-runtimes)
  - [Key Features](#key-features)
  - [Detailed API Examples](#detailed-api-examples)
    - [Secure ID \& UUID Generation](#secure-id--uuid-generation)
    - [Timing-Safe Comparison](#timing-safe-comparison)
    - [Secure URL Construction](#secure-url-construction)
    - [Secure `postMessage` Handling](#secure-postmessage-handling)
    - [Redacted Development Logging](#redacted-development-logging)
    - [Secure LRU Cache](#secure-lru-cache)
    - [Secure API Signing with Worker Integrity](#secure-api-signing-with-worker-integrity)
  - [The Constitutions \& Methodology](#the-constitutions--methodology)
  - [Advanced Topics](#advanced-topics)
    - [Secure Startup Pattern \& Sealing the Kit](#secure-startup-pattern--sealing-the-kit)
    - [Worker Integrity Controls and CSP](#worker-integrity-controls-and-csp)
      - [Blob Workers and Content Security Policy (CSP)](#blob-workers-and-content-security-policy-csp)
      - [Integrity Modes Matrix (summary)](#integrity-modes-matrix-summary)
    - [Bundler Configuration (Vite)](#bundler-configuration-vite)
    - [Optional Dependencies \& Bundle Size](#optional-dependencies--bundle-size)
    - [Production Error Reporting](#production-error-reporting)
    - [Sanitization \& DOM Utilities](#sanitization--dom-utilities)
  - [Testing](#testing)
  - [Contributing](#contributing)
  - [Author and License](#author-and-license)
  - [Acknowledgments](#acknowledgments)

---

## Core Philosophy

This library is built on a set of non-negotiable principles, codified in the included **[Security Constitution](./docs/Constitutions.md)**.

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

Get a cryptographically secure, URL-friendly ID in seconds.

```typescript
import { SIMPLE_API } from "@david-osipov/security-kit";

async function main() {
  // SIMPLE_API provides easy access to the most common functions.
  // This call ensures the Web Crypto API is available and ready.
  const secureId = await SIMPLE_API.generateSecureId(21);

  console.log("Generated a secure ID:", secureId);
  // => "useandom-26T198340PX75pxJACKV" (example)
}

main();
```

## Choosing the right API (security vs convenience)

- Highest assurance (wipeable): use `generateSecureIdBytesSync(byteLength)` / `generateSecureBytesAsync(byteLength)`, then `secureWipe()` promptly.
- Convenience (not wipeable): `generateSecureId(length)`, `generateSecureUUID()`. Do not use for secrets in memory-constrained/high-assurance contexts.
- Feature detection: call `getCryptoCapabilities()` or `hasRandomUUIDSync()`.

## Supported runtimes

- Node.js: >= 18 (recommended >= 20). WebCrypto is required; SubtleCrypto for SRI.
- Browsers: modern evergreen. Use `getCryptoCapabilities()` to branch code paths politely.

## Key Features

- **Modern Cryptography:**
  - Cryptographically secure random number, integer, and byte generation.
  - High-performance, unbiased secure string generation (inspired by `nanoid`).
  - RFC 4122 v4 UUID generation.
  - Secure, non-extractable `CryptoKey` generation for AES-GCM.
  - Timing-attack resistant string comparison functions.
- **Secure Development Helpers:**
  - `secureDevLog`: A development-only logger with automatic redaction of sensitive data.
  - `secureWipe`: Best-effort memory wiping for sensitive buffers.
  - Hardened environment detection (`isDevelopment`, `isProduction`).
  - Rate-limited production error reporter.
- **Secure Startup & Sealing:**
  - A secure startup pattern that freezes the kit's configuration after initialization (`sealSecurityKit`), preventing runtime tampering and privilege escalation.
- **Worker Integrity Controls:**
  - Hardened `SecureApiSigner` with strict integrity modes (`require`, `compute`) to mitigate TOCTOU attacks on web workers.
  - Configurable runtime policies for Blob worker usage and security trade-offs.
- **Security-Hardened LRU Cache:**
  - High-performance, memory-safe cache for sensitive byte arrays with advanced eviction policies (LRU, Segmented LRU, SIEVE).
  - Built-in protections against TOCTOU attacks, memory exhaustion, and data leakage.
  - Automatic buffer zeroization and defensive copying.
- **URL & URI Hardening:**
  - Safely build and modify URLs without string interpolation vulnerabilities.
  - Robust validation and parsing of URL strings and their parameters.
  - RFC 3986 compliant component encoders (`encodeQueryValue`, `encodePathSegment`).
- **Cross-Context Communication:**
  - Hardened `postMessage` utilities that enforce strict origin validation and prevent prototype pollution.
- **DOM & Sanitization:**
  - A `Sanitizer` class to manage `DOMPurify` policies and create Trusted Types.
  - A `DOMValidator` for allowlist-based, secure DOM querying.

## Detailed API Examples

### Secure ID & UUID Generation

Use the `SIMPLE_API` object for the most common cryptographic tasks.

```typescript
import { SIMPLE_API } from "@david-osipov/security-kit";

// Generate a 64-character hexadecimal ID
const hexId = await SIMPLE_API.generateSecureId();

// Generate a standard v4 UUID
const uuid = await SIMPLE_API.generateSecureUUID();

console.log({ hexId, uuid });
```

### Timing-Safe Comparison

Always use `secureCompareAsync` with `{ requireCrypto: true }` for security-critical comparisons like tokens or signatures. This prevents timing attacks and ensures the operation fails loudly if the platform's `SubtleCrypto` API is unavailable.

```typescript
import { SIMPLE_API } from "@david-osipov/security-kit";

const userInput = "user-provided-token";
const secretToken = "a-very-secret-token-from-server";

const areTokensEqual = await SIMPLE_API.secureCompareAsync(
  userInput,
  secretToken,
  { requireCrypto: true }, // Fails loudly if SubtleCrypto is unavailable
);

console.log("Tokens are equal (timing-safe):", areTokensEqual);
```

### Secure URL Construction

Safely construct a URL, preventing common encoding and path traversal vulnerabilities.

```typescript
import { createSecureURL } from "@david-osipov/security-kit";

const url = createSecureURL(
  "https://api.example.com",
  ["users", "search"], // Path segments are safely encoded
  { q: "John Doe", filter: "active+premium" }, // Query params are safely encoded
  "results", // Fragment
);

// Returns: "https://api.example.com/users/search?q=John%20Doe&filter=active%2Bpremium#results"
```

### Secure `postMessage` Handling

Listen for `postMessage` events while enforcing a strict origin allowlist and validating the payload schema.

```typescript
import { createSecurePostMessageListener } from "@david-osipov/security-kit";

const listener = createSecurePostMessageListener({
  allowedOrigins: ["https://trusted-partner.com"],
  onMessage: (data) => {
    console.log("Received trusted message:", data);
  },
  validate: {
    // Enforces the shape of the incoming data object
    type: "string",
    payload: "object",
  },
});

// To clean up the listener when your component unmounts:
// listener.destroy();
```

### Redacted Development Logging

Use `secureDevLog` to log contextual data during development. It automatically redacts sensitive keys to prevent accidental secret leakage in console output. In production builds, this function does nothing.

```typescript
import { secureDevLog } from "@david-osipov/security-kit";

const sensitiveData = {
  userId: 123,
  token: "jwt-token-string-here",
  password: "user-password",
};

// In development, this logs the object with '[REDACTED]' values for token and password.
// In production, this is a no-op.
secureDevLog("info", "AuthComponent", "User logged in", sensitiveData);
```

### Secure LRU Cache

`SecureLRUCache` is a security-hardened, high-performance LRU cache designed for storing sensitive byte arrays. It includes built-in protections against memory exhaustion attacks, timing-based side channels, and data leakage.

```typescript
import { SecureLRUCache, VerifiedByteCache } from "@david-osipov/security-kit";

// Option 1: Use the singleton for simple global caching
const scriptBytes = new TextEncoder().encode('console.log("trusted script");');
VerifiedByteCache.set("https://cdn.example.com/script.js", scriptBytes);

// Later, retrieve for TOCTOU-safe execution
const cachedBytes = VerifiedByteCache.get("https://cdn.example.com/script.js");
if (cachedBytes) {
  const blob = new Blob([cachedBytes], { type: "application/javascript" });
  const worker = new Worker(URL.createObjectURL(blob));
}

// Option 2: Create custom cache instances for advanced use cases
const cache = new SecureLRUCache({
  maxEntries: 100,
  maxBytes: 5 * 1024 * 1024, // 5MB
  defaultTtlMs: 300_000, // 5 minutes
  copyOnGet: true, // Return defensive copies (default: true)
  copyOnSet: true, // Store defensive copies (default: true)
  rejectSharedBuffers: true, // Security: reject SharedArrayBuffer views
  onEvict: (entry) => {
    console.log(
      `Evicted ${entry.url} (${entry.bytesLength} bytes, reason: ${entry.reason})`,
    );
  },
});

// Store sensitive data with automatic expiration and memory management
const tokenData = new TextEncoder().encode("eyJ0eXAiOiJKV1QiLCJhbGc...");
cache.set("user:123:token", tokenData, { ttlMs: 600_000 }); // 10 minutes

// Retrieve data (returns undefined if expired or not found)
const retrievedToken = cache.get("user:123:token");

// Monitor cache performance and health
const stats = cache.getStats();
console.log(
  `Cache: ${stats.size} entries, ${stats.totalBytes} bytes, ${stats.hits}/${stats.hits + stats.misses} hit rate`,
);
```

### Secure API Signing with Worker Integrity

Use `SecureApiSigner` to perform HMAC signing in a separate thread, with strict integrity checks to prevent loading a compromised worker script.

```typescript
import { SecureApiSigner } from "@david-osipov/security-kit";

// In your build process, compute the hash of your worker script:
// shasum -a 256 -b signing-worker.js | cut -d' ' -f1 | xxd -r -p | base64
const WORKER_HASH = "<base64-sha256-of-your-worker-script>";

const signer = await SecureApiSigner.create({
  workerUrl: new URL("/assets/signing-worker.js", location.href),
  secret: new Uint8Array(32), // Use a 32-byte (256-bit) secret
  integrity: "require", // Recommended for production
  expectedWorkerScriptHash: WORKER_HASH,
});

const signaturePayload = await signer.sign({ message: "hello" });
console.log("Signed payload:", signaturePayload);
```

## The Constitutions & Methodology

This library is more than just code; it's an architecture.

- The **[Security Constitution](./docs/Constitutions.md)** is a mandatory read for any team using this library. It serves as a single source of truth for the non-negotiable rules and principles that this library enforces.
- The **[Development Methodology](./docs/METHODOLOGY.md)** document outlines the rigorous, AI-assisted workflow used to create, validate, and harden this toolkit with full transparency.

## Advanced Topics

### Secure Startup Pattern & Sealing the Kit

The library enforces a secure startup pattern. Configuration and secret-bearing "capabilities" (like a signer) should be created once during application bootstrap. Afterward, the kit should be **sealed** to make its configuration immutable, hardening your app against runtime tampering or malicious dependency behavior.

```typescript
import { sealSecurityKit, setAppEnvironment } from "@david-osipov/security-kit";

// 1. Perform all configuration at startup.
setAppEnvironment("production");
// ... create signing capabilities, etc.

// 2. Seal the kit before accepting traffic.
// `freezeConfig()` is an alias for `sealSecurityKit()`.
sealSecurityKit();

// 3. Any further attempts to configure the library will now throw an error.
// setAppEnvironment("development"); // Throws InvalidConfigurationError
```

### Worker Integrity Controls and CSP

The `SecureApiSigner` defaults to the strictest integrity mode (`require`), which demands a pre-computed hash of the worker script. This is the best way to mitigate Time-of-Check to Time-of-Use (TOCTOU) attacks.

- **`integrity: "require"` (Default, Recommended):** You must provide `expectedWorkerScriptHash`. The library fetches the worker, verifies its hash, and only then proceeds.
- **`integrity: "compute"`:** The library fetches the worker and computes the hash at runtime. This is convenient for development but is **blocked in production by default** unless you explicitly opt-in via runtime policy, as it leaves a small TOCTOU window.
- **`integrity: "none"`:** Disables all integrity checks. **Forbidden in production.**

#### Blob Workers and Content Security Policy (CSP)

To completely eliminate the TOCTOU window when using `integrity: "compute"` or `integrity: "require"`, the library can create the worker from a `Blob` of the verified script bytes. This requires your Content Security Policy (CSP) to allow `blob:` URLs.

- **Recommended CSP:** `worker-src 'self' blob:;`
- If Blob workers are blocked by CSP, the library will fall back to instantiating the worker by its URL, which re-introduces the TOCTOU risk.

#### Integrity Modes Matrix (summary)

- **`require` + Blob usable:** Executes from verified bytes (no TOCTOU). In production, HTTPS is enforced for `workerUrl`.
- **`require` + Blob not usable:** Library verifies script bytes but instantiates by URL; a TOCTOU window remains. Recommended: enable Blob workers via CSP (`worker-src blob:`) and runtime policy, or precompute hashes and serve immutable worker assets.
- **`compute`:** Dev-only by default; in production requires BOTH a global override (runtime policy) AND a per-call override. If Blob is allowed, the Worker is created from the verified bytes to eliminate TOCTOU.

### Bundler Configuration (Vite)

This library includes test-only code that is automatically removed from production builds using a global `__TEST__` flag. To enable this Dead Code Elimination (DCE), you must configure your bundler.

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

### Optional Dependencies & Bundle Size

Some features (fast fallbacks and convenience parsers) are provided as optional dependencies to keep the core runtime small and secure by default. The package declares a few optional packages such as `hash-wasm`, `fast-sha256`, `css-what`, and `lru-cache` — they are only required in environments where the native Web Crypto API or other platform capabilities are unavailable.

- If you rely on modern browsers or Node >= 18 with Web Crypto available, you do not need to install these optional packages; the kit will use the native secure implementations.
- If you want the bundled fallbacks (for older runtimes or convenience), install the optional packages in your project.

### Production Error Reporting

The kit includes a rate-limited, centralized production error reporter. Configure it once at startup.

```typescript
import {
  setProductionErrorHandler,
  configureErrorReporter,
  reportProdError,
} from "@david-osipov/security-kit";

// Configure on app startup
configureErrorReporter({ burst: 10, refillRatePerSec: 2 });
setProductionErrorHandler((err, ctx) => {
  // Forward to your telemetry pipeline (Sentry, Datadog, etc.)
  console.error("PRODUCTION ERROR:", err, ctx);
});

// Manually report a critical error (this call is rate-limited)
reportProdError(new Error("Payment failed"), { module: "billing" });
```

### Sanitization & DOM Utilities

The library exposes a `Sanitizer` class that manages named `DOMPurify` configurations and can create Trusted Types policies. `DOMPurify` is a peer dependency, allowing you to provide the instance that matches your environment (browser, JSDOM, etc.).

```typescript
import {
  Sanitizer,
  STRICT_HTML_POLICY_CONFIG,
} from "@david-osipov/security-kit";
import DOMPurify from "dompurify";

// In a browser environment
const sanitizer = new Sanitizer(DOMPurify, {
  strict: STRICT_HTML_POLICY_CONFIG,
});

const safeHtml = sanitizer.getSanitizedString(
  "<img src=x onerror=alert(1)>",
  "strict",
);
// => "<img src="x">"
```

## Testing

This repository uses Vitest for a comprehensive test suite that validates correctness, security properties, and resilience against edge cases.

```bash
# Run the full test suite
npm test

# Run tests with coverage reporting
npm run coverage
```

The repository also contains opt-in performance benchmarks for security-sensitive modules. These are intended for local profiling and are excluded from normal CI runs.

```bash
# Run all performance tests
npm run perf
```

## Contributing

Contributions are welcome! Please read the **[Security Constitution](./docs/Constitutions.md)** and ensure any pull requests adhere to its principles and include corresponding tests.

## Author and License

- **Author:** This project was architected and directed by **David Osipov**, an AI-Driven B2B Lead Product Manager. You can learn more about my work and philosophy at [david-osipov.vision](https://david-osipov.vision).
- **ISNI:** [0000 0005 1802 960X](https://isni.org/isni/000000051802960X)
- **ORCID:** [0009-0005-2713-9242](https://orcid.org/0009-0005-2713-9242)
- **Contact:** <personal@david-osipov.vision>
- **License:** GNU Lesser General Public License v3.0 or later (SPDX-License-Identifier: LGPL-3.0-or-later)

## Acknowledgments

This security-kit stands on the shoulders of giants. We extend our gratitude to the developers of the open-source software that inspired and enabled this project.

- The `SecureLRUCache` implementation is a hardened and security-focused version of the excellent [lru-cache](https://github.com/isaacs/node-lru-cache) library by Isaac Z. Schlueter and its contributors.
