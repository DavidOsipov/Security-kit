User documentation for Security Kit

This directory contains user-facing documentation describing how to use the Security Kit library safely and ergonomically.

# Overview

Security Kit is an opinionated, zero-dependency TypeScript library providing secure primitives for web applications. It enforces Zero-Trust defaults and is designed for developers who need hardened, auditable, and testable security utilities built on native Web APIs.

# Quick links

- API reference: ../Documentation.md (high-level library docs)
- URL utilities: ../postMessage.md (detailed examples)

# Getting started

## Install

Install via npm:

```bash
npm install @david-osipov/security-kit
```

## Basic usage

Import the public API and call functions. Example: validate and construct URLs safely.

```ts
import {
  validateURL,
  createSecureURL,
  setRuntimePolicy,
} from "@david-osipov/security-kit";

// validate a URL using the default safe policy (strict)
const res = validateURL("https://example.com");
if (!res.ok) throw res.error;
console.log(res.url.href);

// create a URL from parts
const url = createSecureURL("https://example.com", ["path", "to", "resource"], {
  q: "a",
});
console.log(url);

// enable permissive runtime policy (not recommended in production)
setRuntimePolicy({ allowCallerSchemesOutsidePolicy: true });
```

## Security-first notes

- The library enforces strict defaults (OWASP ASVS L3). By default, a caller-provided set of allowed schemes must intersect the library's configured SAFE_SCHEMES or validation will fail.
- Dangerous schemes (javascript:, data:, file:, blob:, vbscript:, about:) are always blocked.
- Sensitive operations use constant-time comparisons and explicit memory wiping where applicable.

## Where to read more

- Project README: ../../README.md
- Security constitutions: ../Constitutions/

## Support and issues

Please open issues on the GitHub repository at https://github.com/david-osipov/Security-Kit/issues
