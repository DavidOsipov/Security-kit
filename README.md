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

*   🛡️ **Secure by Default:** The default state of every function is the most secure state. Insecure actions are forbidden.
*   🏰 **Defense in Depth:** Multiple, independent security controls are layered to protect against failure in any single component.
*   🔒 **Principle of Least Privilege:** Every component operates with the minimum level of access necessary to perform its function.
*   💥 **Fail Loudly, Fail Safely:** In the face of an error or unavailable security primitive, the system throws a specific error and never silently falls back to an insecure alternative.
*   ✅ **Verifiable Security:** A security control is considered non-existent until it is validated by an automated, adversarial test.

## Installation

```bash
npm install @david-osipov/security-kit
```

## Quick Start

The recommended way to initialize the library is to call an async function first, then seal the kit at your application's startup.

```typescript
import { SIMPLE_API, sealSecurityKit, isDevelopment } from '@david-osipov/security-kit';

async function initializeApp() {
  // 1. Call an async function first. This ensures the crypto API is ready.
  const secureId = await SIMPLE_API.generateSecureId(32);
  console.log('Generated an initial secure ID:', secureId);

  // 2. NOW, it is safe to seal the kit.
  // This prevents any further configuration changes, hardening your app against runtime tampering.
  sealSecurityKit();
  console.log('Security Kit is sealed.');

  // 3. Continue using the library.
  const uuid = await SIMPLE_API.generateSecureUUID();
  console.log('Secure UUID:', uuid);

  // Perform a timing-attack-resistant string comparison
  const userInput = 'user-provided-token';
  const secretToken = 'a-very-secret-token-from-server';
  const areTokensEqual = SIMPLE_API.secureCompare(userInput, secretToken);

  console.log('Tokens are equal (timing-safe):', areTokensEqual);

  // Log a message that will only appear in development environments
  if (isDevelopment()) {
    console.log('This is a development build.');
  }
}

initializeApp();
```

## Key Features

*   **Modern Cryptography:**
    *   Cryptographically secure random number, integer, and byte generation.
    *   High-performance, unbiased secure string generation (inspired by `nanoid`).
    *   RFC 4122 v4 UUID generation.
    *   Secure, non-extractable `CryptoKey` generation for AES-GCM.
    *   Timing-attack resistant `secureCompare` and `secureCompareAsync` functions.
*   **Secure Development Helpers:**
    *   `secureDevLog`: A development-only logger with automatic redaction of sensitive data.
    *   `secureWipe`: Best-effort memory wiping for sensitive buffers.
    *   Hardened environment detection (`isDevelopment`, `isProduction`).
    *   Rate-limited production error reporter.
*   **URL & URI Hardening:**
    *   `createSecureURL` and `updateURLParams`: Safely build and modify URLs without string interpolation vulnerabilities.
    *   `validateURL` and `parseURLParams`: Robust validation and parsing of URL strings and their parameters.
    *   RFC 3986 compliant component encoders (`encodeQueryValue`, `encodePathSegment`).
*   **Cross-Context Communication:**
    *   `sendSecurePostMessage` and `createSecurePostMessageListener` enforce strict origin validation, forbidding wildcards.
    *   Hardened payload validation to prevent oversized payloads and prototype pollution.
*   **Subresource Integrity (SRI):**
    *   `generateSRI` to create integrity hashes for your assets.

## The Security Constitution

This library is more than just code; it's an architecture. The included [`Security Consitution.md`](./Security%20Consitution.md) is a mandatory read for any team using this library. It serves as a single source of truth for developers and security engineers, outlining the non-negotiable rules and principles that this library enforces.

## API Documentation

For a detailed understanding of every function, please refer to the JSDoc comments within the `index.ts` source file. Here are a few highlights of the advanced API:

#### `createSecureURL(base, pathSegments?, queryParams?, fragment?)`

Safely constructs a URL, preventing common encoding and path traversal vulnerabilities.

```typescript
import { createSecureURL } from '@david-osipov/security-kit';

const url = createSecureURL(
  'https://api.example.com',
  ['users', 'search'],
  { q: 'John Doe', filter: 'active+premium' },
  'results'
);
// Returns: "https://api.example.com/users/search?q=John%20Doe&filter=active%2Bpremium#results"
```

#### `createSecurePostMessageListener(options)`

Listens for `postMessage` events while enforcing a strict origin allowlist and validating the payload.

```typescript
import { createSecurePostMessageListener } from '@david-osipov/security-kit';

const listener = createSecurePostMessageListener({
  allowedOrigins: ['https://trusted-partner.com'],
  onMessage: (data) => {
    console.log('Received trusted message:', data);
  },
  validate: {
    type: 'string',
    payload: 'object'
  }
});

// Don't forget to clean up!
// listener.destroy();
```

#### `secureDevLog(level, component, message, context?)`

A development-only logger that automatically redacts sensitive keys from context objects to prevent accidental secret leakage in console output.

```typescript
import { secureDevLog } from '@david-osipov/security-kit';

const sensitiveData = {
  userId: 123,
  token: 'jwt-token-string-here',
  password: 'user-password'
};

// In development, this will log the object with '[REDACTED]' values for token and password.
// In production, this function does nothing.
secureDevLog('info', 'AuthComponent', 'User logged in', sensitiveData);
```

## For Library Consumers & Test Environments

This library includes test-only code that is automatically removed from production builds using a global `__TEST__` flag. To leverage this Dead Code Elimination (DCE), you must configure your bundler.

**Example for Vite (`vite.config.ts`):**
```typescript
import { defineConfig } from 'vite';

export default defineConfig({
  define: {
    // This makes the flag available in your code
    __TEST__: process.env.NODE_ENV === 'test',
  },
});
```
This ensures that functions like `__test_resetCryptoStateForUnitTests` do not exist in your final production bundle.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue. If you'd like to contribute code, please fork the repository and submit a pull request.

Please note that this is a personal project maintained on a best-effort basis.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

---

Authored and maintained by **David Osipov**.
*   Website: [https://david-osipov.vision](https://david-osipov.vision)
*   ISNI: [0000 0005 1802 960X](https://isni.org/isni/000000051802960X)
