# Security-Kit

![NPM Version](https://img.shields.io/npm/v/@david-osipov/security-kit?style=for-the-badge)
![License](https://img.shields.io/npm/l/@david-osipov/security-kit?style=for-the-badge)
![Build Status](https://img.shields.io/github/actions/workflow/status/david-osipov/Security-Kit/ci.yml?branch=main&style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)

![Security-kit logo](https://github.com/user-attachments/assets/4fde77c1-9510-4b55-8e19-83f7be42201a)

## Security-Kit is not just a collection of utilities; it's a security philosophy you can install.

This is a comprehensive, opinionated, and modern security toolkit for browser and server-side JavaScript applications. It provides both cryptographic primitives and safe development helpers, all designed to be the reference implementation for a project's **Security Constitution**. It is built on a **Zero Trust** philosophy, assuming no part of the system is infallible.

The entire library is written in TypeScript, has **zero production dependencies**, and leverages the native **Web Crypto API** for maximum performance and security in modern environments.

---

### ⚠️ Security & Use Case Disclaimer

This library was designed and developed with the stringent principles of the **OWASP Application Security Verification Standard (ASVS) Level 3** as its guiding architectural blueprint. The goal is to provide a toolkit that is secure by default, resilient against common web vulnerabilities, and built upon a foundation of verifiable security patterns as outlined in the project's [Security Constitution](./docs/Constitutions/Security_Constitution.md).

However, it is crucial for users to understand the following:

1.  **This library has not undergone a formal, independent security audit.** While the development methodology is rigorous and AI-assisted, it is not a substitute for a comprehensive audit by a professional security firm. Until an audit has been conducted, this library should be considered insecure.

2.  **Do not use this library as a drop-in solution where a specific OWASP ASVS Level (e.g., L1, L2, or L3) is a formal contractual or regulatory requirement.** Compliance with the ASVS is a property of a fully-audited application, not a single component.

#### Intended Use Case

This library is intended for developers and teams who need a robust, security-hardened toolkit to build upon. It is designed to significantly elevate the security posture of a typical web application and to serve as a powerful component within a broader, defense-in-depth security strategy.

#### Shared Responsibility

The security of your final application is a shared responsibility. Users of this library are responsible for:
*   Implementing it correctly according to best practices.
*   Conducting their own security testing and code reviews.
*   Ensuring their overall application architecture is secure.

This library is a powerful tool to help you build secure applications, but it is not a silver bullet.

---

## Table of Contents

- [Core Philosophy](#core-philosophy)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Key Features](#key-features)
- [The Centralized Configuration System](#the-centralized-configuration-system)
- [Detailed API Examples](#detailed-api-examples)
  - [Secure ID & Secret Handling](#secure-id--secret-handling)
  - [Timing-Safe Comparison](#timing-safe-comparison)
  - [Secure URL Construction & Hardening](#secure-url-construction--hardening)
  - [Secure `postMessage` Handling](#secure-postmessage-handling)
  - [Secure API Signing with Worker Integrity](#secure-api-signing-with-worker-integrity)
  - [Server-Side Signature Verification](#server-side-signature-verification)
  - [Secure LRU Cache](#secure-lru-cache)
  - [Secure DOM Validation & Sanitization](#secure-dom-validation--sanitization)
  - [Redacted Development Logging](#redacted-development-logging)
- [Advanced Topics](#advanced-topics)
  - [Secure Startup Pattern & Sealing the Kit](#secure-startup-pattern--sealing-the-kit)
  - [Secret Length Policy](#secret-length-policy)
  - [Canonicalization for Signatures](#canonicalization-for-signatures)
  - [Worker Integrity Controls and CSP](#worker-integrity-controls-and-csp)
  - [Production Telemetry & Error Reporting](#production-telemetry--error-reporting)
  - [Bundler Configuration (Vite)](#bundler-configuration-vite)
- [Deno + JSR Support](#deno--jsr-support)
- [The Constitutions & Methodology](#the-constitutions--methodology)
- [Contributing](#contributing)
- [Author and License](#author-and-license)

---

## Core Philosophy

This library is built on a set of non-negotiable principles, codified in the included **[Security Constitution](./docs/Constitutions/Security_Constitution.md)**.

- 🛡️ **Secure by Default:** The default state of every function is the most secure state. Insecure actions are forbidden.
- 🏰 **Defense in Depth:** Multiple, independent security controls are layered to protect against failure in any single component.
- 🔒 **Principle of Least Privilege:** Every component operates with the minimum level of access necessary to perform its function.
- 💥 **Fail Loudly, Fail Safely:** In the face of an error or unavailable security primitive, the system throws a specific, typed error and never silently falls back to an insecure alternative.
- ✅ **Verifiable Security:** A security control is considered non-existent until it is validated by an automated, adversarial test. This is enforced by an extremely strict ESLint configuration with custom security rules.

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
  const secureId = await SIMPLE_API.generateSecureId(21);
  const uuid = await SIMPLE_API.generateSecureUUID();

  console.log("Generated a secure ID:", secureId);
  console.log("Generated a secure UUID:", uuid);
}

main();
```

## Key Features

- **Modern Cryptography:**
  - Cryptographically secure random number, integer, and byte generation.
  - High-performance, unbiased secure string generation (inspired by `nanoid`).
  - RFC 4122 v4 UUID generation.
  - Timing-attack resistant string and byte comparison functions.
  - Secure, non-extractable `CryptoKey` generation for AES-GCM and Subresource Integrity (SRI) generation.

- **Secure API Signing:**
  - **`SecureApiSigner`:** Performs HMAC signing in a separate Web Worker to isolate secrets from the main thread, complete with a built-in **circuit breaker** for resilience.
  - **Worker Integrity:** Enforces strict integrity modes (`require`, `compute`) to mitigate TOCTOU attacks on worker scripts.
  - **Server-Side Verification:** Includes `verifyApiRequestSignature` with a pluggable `INonceStore` for robust replay attack protection. A production-ready `RedisNonceStore` is available.

- **URL & URI Hardening:**
  - Safely build, parse, and modify URLs with protection against path traversal, scheme confusion, and prototype pollution.
  - Advanced, configurable validation policies for hostnames (RFC 1123), IPv4 ambiguity, and IDNA (Punycode) conversion.
  - RFC 3986 compliant component encoders (`encodeQueryValue`, `encodePathSegment`).

- **Secure LRU Cache:**
  - **`SecureLRUCache`:** A high-performance, memory-safe cache for sensitive byte arrays.
  - **Advanced Eviction Policies:** Supports LRU, Segmented LRU, Second-Chance, and SIEVE algorithms, configurable via profiles.
  - **Memory Safety:** Features automatic buffer zeroization, defensive copying, and rejection of `SharedArrayBuffer`.
  - **`VerifiedByteCache`:** A convenient singleton for caching verified script bytes or other binary assets.

- **Cross-Context Communication:**
  - Hardened `postMessage` utilities that enforce a strict origin allowlist, prevent prototype pollution, and apply configurable traversal limits (depth, node count, keys) to prevent resource exhaustion attacks.

- **DOM & Sanitization:**
  - **`Sanitizer`:** A hardened wrapper for `DOMPurify` to manage named sanitization policies (e.g., `STRICT_HTML_POLICY_CONFIG`) and create Trusted Types.
  - **`DOMValidator`:** A powerful utility for allowlist-based, secure DOM querying with rate-limiting and TTL-based element re-validation.

- **Secure Development & Operations:**
  - **Centralized Configuration:** A single, sealable API to configure all library behaviors.
  - **`secureDevLog`:** A development-only logger with automatic redaction of sensitive data.
  - **`secureWipe` & `withSecureBuffer`:** Best-effort memory wiping and secure lifecycle patterns for secrets.
  - **Typed Errors & Safe Logging:** A rich set of custom, typed errors and a `sanitizeErrorForLogs` utility with ReDoS-hardened stack fingerprinting.
  - **Telemetry & Reporting:** A rate-limited production error reporter and a telemetry hook for monitoring internal security events.

## The Centralized Configuration System

Nearly every module in Security-Kit is configurable through a centralized, type-safe API. This allows you to tune performance, set security boundaries, and define policies from a single source of truth before sealing the kit at startup.

| Configuration Function        | Controls                                                              |
| ----------------------------- | --------------------------------------------------------------------- |
| `setAppEnvironment()`         | Sets the environment to `development` or `production`.                |
| `setPostMessageConfig()`      | Limits for `postMessage` payloads (size, depth, nodes, keys).         |
| `setSecureLRUProfiles()`      | Defines and selects cache eviction profiles (e.g., `low-latency`).    |
| `setUrlHardeningConfig()`     | Toggles for strict URL parsing (IPv4, IDNA, special schemes).         |
| `setUrlPolicyConfig()`        | Defines the application-wide list of safe URL schemes.                |
| `setRuntimePolicy()`          | Manages global security policies like allowing Blob workers.          |
| `setCanonicalConfig()`        | Sets limits for deterministic JSON serialization.                     |
| `setHandshakeConfig()`        | Configures nonce formats and lengths for the API signer.              |
| `setTimingConfig()`           | Adjusts timing equalization budgets for tests.                        |

```typescript
import { setPostMessageConfig, setUrlHardeningConfig } from "@david-osipov/security-kit";

// Tune postMessage limits for higher throughput
setPostMessageConfig({
  maxPayloadBytes: 64 * 1024, // 64 KiB
  maxPayloadDepth: 12,
});

// Enable stricter URL parsing rules globally
setUrlHardeningConfig({
  strictIPv4AmbiguityChecks: true, // Reject '127.1' or '0177.0.0.1'
});
```

## Detailed API Examples

### Secure ID & Secret Handling

For non-sensitive identifiers, use the convenient string-based APIs. For secrets, always use byte-based APIs with a secure lifecycle pattern to ensure memory is wiped.

```typescript
import { SIMPLE_API, withSecureBuffer } from "@david-osipov/security-kit";

// Convenience API for non-secrets (string is not wipeable)
const uuid = await SIMPLE_API.generateSecureUUID();

// Recommended pattern for handling secrets
withSecureBuffer(32, (secretKey) => {
  // `secretKey` is a secure Uint8Array that will be wiped automatically
  // when this function returns or throws. Use it here.
});
```

### Timing-Safe Comparison

Always use `secureCompareAsync` with `{ requireCrypto: true }` for security-critical comparisons like tokens or signatures.

```typescript
import { SIMPLE_API } from "@david-osipov/security-kit";

const userInput = "user-provided-token";
const secretToken = "a-very-secret-token-from-server";

const areTokensEqual = await SIMPLE_API.secureCompareAsync(
  userInput,
  secretToken,
  { requireCrypto: true } // Fails loudly if SubtleCrypto is unavailable
);
```

### Secure URL Construction & Hardening

Safely construct and validate URLs, preventing common vulnerabilities.

```typescript
import { createSecureURL, validateURL } from "@david-osipov/security-kit";

// Safely build a URL
const url = createSecureURL(
  "https://api.example.com/v1",
  ["users", "search"], // Path segments are safely encoded
  { q: "John Doe", filter: "active" }, // Query params are safely encoded
  "results" // Fragment
);
// => "https://api.example.com/v1/users/search?q=John%20Doe&filter=active#results"

// Validate an external URL
const result = validateURL("https://malicious.com/path?q=<script>alert(1)</script>");
if (!result.ok) {
  console.error("Invalid URL:", result.error.message);
}
```

### Secure `postMessage` Handling

Listen for `postMessage` events while enforcing a strict origin allowlist and validating the payload schema. The listener automatically hardens payloads against prototype pollution and resource exhaustion.

```typescript
import { createSecurePostMessageListener } from "@david-osipov/security-kit";

const listener = createSecurePostMessageListener({
  allowedOrigins: ["https://trusted-partner.com"],
  onMessage: (data, context) => {
    console.log(`Received trusted message from ${context.origin}:`, data);
  },
  // Enforces the shape of the incoming data object. Required in production.
  validate: {
    type: "string",
    payload: "object",
  },
});

// To clean up the listener:
// listener.destroy();
```

### Secure API Signing with Worker Integrity

Use `SecureApiSigner` to perform HMAC signing in a separate thread, with strict integrity checks and a built-in circuit breaker for resilience.

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

const signaturePayload = await signer.sign(
  { data: "payload to sign" },
  { method: "POST", path: "/api/v1/resource" }
);
```

### Server-Side Signature Verification

The library provides a dedicated server-side entry point: `@david-osipov/security-kit/server`. Use `verifyApiRequestSignature` with a production-ready nonce store to prevent replay attacks.

```typescript
import {
  verifyApiRequestSignature,
  RedisNonceStore, // Production-ready implementation
} from "@david-osipov/security-kit/server";
import { createClient } from "redis";

const redisClient = createClient(); // Your configured Redis client
const nonceStore = new RedisNonceStore(redisClient);
const serverSecret = new Uint8Array(32); // Must match the client's secret

async function handleRequest(req) {
  const { signature, nonce, timestamp, kid } = req.headers;
  try {
    await verifyApiRequestSignature(
      { secret: serverSecret, payload: req.body, nonce, timestamp, signatureBase64: signature, method: req.method, path: req.path, kid },
      nonceStore
    );
    // Signature is valid, process the request
  } catch (error) {
    // Handle verification failure (e.g., send 401 Unauthorized)
  }
}
```

### Secure LRU Cache

`SecureLRUCache` is a security-hardened, high-performance cache for sensitive byte arrays. Use the `VerifiedByteCache` singleton for simple global caching.

```typescript
import { VerifiedByteCache } from "@david-osipov/security-kit";

// Store verified script bytes
const scriptBytes = new TextEncoder().encode('console.log("trusted script");');
VerifiedByteCache.set("https://cdn.example.com/script.js", scriptBytes);

// Later, retrieve for TOCTOU-safe execution
const cachedBytes = VerifiedByteCache.get("https://cdn.example.com/script.js");
if (cachedBytes) {
  const blob = new Blob([cachedBytes], { type: "application/javascript" });
  const worker = new Worker(URL.createObjectURL(blob));
}
```

### Secure DOM Validation & Sanitization

Use `DOMValidator` to query elements only within trusted parts of your application, and `Sanitizer` to manage `DOMPurify` policies.

```typescript
import { DOMValidator, Sanitizer, STRICT_HTML_POLICY_CONFIG } from "@david-osipov/security-kit";
import DOMPurify from "dompurify"; // Peer dependency

// Configure the validator with your app's trusted roots
const validator = new DOMValidator({
  allowedRootSelectors: new Set(["#main-content", "#modal-container"]),
});

// This query will only return elements inside the allowed roots
const buttons = validator.queryAllSafely("button.submit");

// Create a sanitizer with named policies
const sanitizer = new Sanitizer(DOMPurify, { strict: STRICT_HTML_POLICY_CONFIG });
const safeHtml = sanitizer.getSanitizedString("<img src=x onerror=alert(1)>", "strict");
// => "<img src="x">"
```

### Redacted Development Logging

Use `secureDevLog` to log contextual data during development. It automatically redacts sensitive keys to prevent accidental secret leakage. In production builds, this function is a no-op.

```typescript
import { secureDevLog } from "@david-osipov/security-kit";

const sensitiveData = { userId: 123, token: "jwt-token-string-here", password: "user-password" };
secureDevLog("info", "AuthComponent", "User logged in", sensitiveData);
// In dev, logs: { "userId": 123, "token": "[REDACTED]", "password": "[REDACTED]" }
```

## Advanced Topics

### Secure Startup Pattern & Sealing the Kit

The library enforces a secure startup pattern. All configuration should be performed once during application bootstrap. Afterward, the kit should be **sealed** to make its configuration immutable.

```typescript
import { sealSecurityKit, setAppEnvironment } from "@david-osipov/security-kit";

// 1. Perform all configuration at startup.
setAppEnvironment("production");

// 2. Seal the kit before accepting traffic.
sealSecurityKit();

// 3. Any further attempts to configure the library will now throw an error.
// setAppEnvironment("development"); // Throws InvalidConfigurationError
```

### Secret Length Policy

Security-kit enforces a minimum secret length for HMAC-based API signing and verification to protect against weak keys.

-   **Minimum accepted length: 32 bytes (256 bits)** is required for production.
-   If you use shorter secrets, rotate to a 32-byte key. For legacy systems, consider using a KDF (like HKDF-SHA256) to derive a 32-byte key from your existing secret.

### Canonicalization for Signatures

For API signing to be reliable, both the client and server must produce the exact same string representation of the payload. The `toCanonicalValue` and `safeStableStringify` functions provide this guarantee. They are **deterministic**, sort object keys, handle circular references, and are hardened against **prototype pollution** by rejecting forbidden keys (`__proto__`, etc.) and insecure data types.

### Worker Integrity Controls and CSP

The `SecureApiSigner` defaults to the strictest integrity mode (`require`), which demands a pre-computed hash of the worker script. This is the best way to mitigate Time-of-Check to Time-of-Use (TOCTOU) attacks.

-   **`integrity: "require"` (Default, Recommended):** You must provide `expectedWorkerScriptHash`. The library fetches the worker, verifies its hash, and only then proceeds.
-   **`integrity: "compute"`:** The library fetches the worker and computes the hash at runtime. This is convenient for development but is **blocked in production by default** unless you explicitly opt-in, as it leaves a small TOCTOU window.
-   **`integrity: "none"`:** Disables all integrity checks. **Forbidden in production.**

To completely eliminate the TOCTOU window, the library can create the worker from a `Blob` of the verified script bytes. This requires your Content Security Policy (CSP) to allow `blob:` URLs in `worker-src`.

-   **Recommended CSP:** `worker-src 'self' blob:;`

### Production Telemetry & Error Reporting

The kit includes a rate-limited production error reporter and a telemetry hook for monitoring internal events.

```typescript
import {
  setProductionErrorHandler,
  configureErrorReporter,
  registerTelemetry,
} from "@david-osipov/security-kit";

// Configure error reporting
configureErrorReporter({ burst: 10, refillRatePerSec: 2 });
setProductionErrorHandler((err, ctx) => {
  // Forward to your telemetry pipeline (Sentry, Datadog, etc.)
});

// Register a telemetry hook for internal metrics
registerTelemetry((name, value, tags) => {
  // Send to your metrics backend (Prometheus, etc.)
  // Example: 'secureCompare.fallback', 1, { reason: 'crypto-unavailable' }
});
```

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

## Deno + JSR Support

This repository includes **hardened Deno/JSR support** to reduce npm supply-chain risk. Our approach provides defense-in-depth against malicious dependencies through Deno's permission sandboxing and native security model.

### Quick Start with Deno

```bash
# Run Deno tests directly on source TypeScript
deno task test

# Build hardened npm package via dnt (Deno-to-Node transformation)
deno task build
```

## The Constitutions & Methodology

This library is more than just code; it's an architecture.

-   The **[Security Constitution](./docs/Constitutions/Security_Constitution.md)** is a mandatory read for any team using this library. It serves as a single source of truth for the non-negotiable rules and principles that this library enforces.
-   The **[Development Methodology](./docs/Methodology/METHODOLOGY.md)** document outlines the rigorous, AI-assisted workflow used to create, validate, and harden this toolkit with full transparency.

## Contributing

Contributions are welcome! Please read the **[Security Constitution](./docs/Constitutions/Security_Constitution.md)** and ensure any pull requests adhere to its principles and include corresponding tests.

## Author and License

-   **Author:** This project was architected and directed by **David Osipov**, an AI-Driven B2B Lead Product Manager. You can learn more about my work and philosophy at [david-osipov.vision](https://david-osipov.vision).
-   **ISNI:** [0000 0005 1802 960X](https://isni.org/isni/000000051802960X)
-   **ORCID:** [0009-0005-2713-9242](https://orcid.org/0009-0005-2713-9242)
-   **Contact:** <personal@david-osipov.vision>
-   **License:** GNU Lesser General Public License v3.0 or later (SPDX-License-Identifier: LGPL-3.0-or-later)
