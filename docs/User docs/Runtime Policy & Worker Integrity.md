# Security Kit — Runtime Policy & Worker Integrity (User Documentation)

This document explains the new runtime policy controls, integrity modes, Blob worker behavior, configuration examples, migration notes, and error codes introduced in the Security Kit.

## Overview

Security Kit enforces a secure-by-default posture aligned to the project's Security Constitution and OWASP ASVS Level 3.

Key features introduced:

- Default worker integrity mode `require` (strict).
- Config-gated Blob worker support to eliminate TOCTOU when `compute` is used.
- Central `RuntimePolicyConfig` in `src/config.ts` to manage Blob and integrity policies.
- Typed `SecurityKitError` with machine-readable error codes.
- Increased server-side minimum secret length for verification (32 bytes).
- Max canonical payload size enforcement to mitigate DoS.

## Runtime Policy (central control)

The runtime policy is exposed via `getRuntimePolicy()` and adjusted via `setRuntimePolicy()` in `src/config.ts`.

Runtime policy fields:

- `allowBlobUrls: boolean` — Whether Blob URLs are generally allowed (default: true in development, false in production).
- `allowBlobWorkers: boolean` — Allow creating Workers from Blob URLs (default: false in production). When enabled, Security Kit will use verified worker bytes to create the Worker from a Blob to eliminate TOCTOU.
- `allowComputeIntegrityInProductionDefault: boolean` — Global default: if true, allows `integrity: 'compute'` in production unless the per-call init explicitly forbids it.

Example:

```ts
import { setRuntimePolicy } from "../src/config";

setRuntimePolicy({
  allowBlobWorkers: true,
  allowComputeIntegrityInProductionDefault: false,
});
```

> Note: Changing runtime policy after `sealSecurityKit()` has been called will throw an error.

## Integrity Modes (in `SecureApiSignerInit`)

`SecureApiSigner` supports three integrity modes:

- `require` (DEFAULT): The caller must provide `expectedWorkerScriptHash` (base64 SHA-256). The library will fetch the worker script and verify the hash matches. This is the recommended, secure option for production.

- `compute`: The library will fetch the worker script, compute its SHA-256, and (if `allowBlobWorkers` is enabled) create a Worker from a Blob made from the verified bytes (no TOCTOU). In production, `compute` is blocked unless both global and per-call overrides are provided.

- `none`: Skip any integrity checks (not recommended for production)

### Example: Strict (recommended)

```ts
import { SecureApiSigner } from "security-kit";

const signer = await SecureApiSigner.create({
  workerUrl: new URL("/assets/signing-worker.js", location.href),
  secret: secretArrayBuffer,
  integrity: "require",
  expectedWorkerScriptHash: "<base64-sha256>",
});
```

### Example: Compute + Blob (portable + safe when allowed)

```ts
import { SecureApiSigner } from "security-kit";
import { setRuntimePolicy } from "../src/config";

setRuntimePolicy({ allowBlobWorkers: true });

const signer = await SecureApiSigner.create({
  workerUrl: "/assets/signing-worker.js",
  secret: secretArrayBuffer,
  integrity: "compute",
  allowComputeIntegrityInProduction: false, // per-call guard
});
```

> When `allowBlobWorkers` is `true`, the library stores verified bytes in a short-lived in-memory cache and uses `URL.createObjectURL` to create a Blob-based Worker. The cache has TTL and size limits to avoid memory abuse.

## CSP / Deployment Notes

- Creating Blob-based Workers may require CSP changes such as `worker-src blob:` or broader `script-src` adjustments depending on your environment and whether the worker uses modules that import other resources.
- Blob Workers can be blocked by some CSP policies. In that case the library will throw an error with code `E_CSP_BLOCKED`.
- For maximum security, prefer `integrity: "require"` with CI-generated hashes for fingerprinted worker assets. This can be automated in build pipelines.

## Integrity Modes Matrix (detailed)

- require + Blob usable
  - Behavior: Library verifies the hash and creates a Worker from the verified bytes (Blob), eliminating TOCTOU.
  - Requirements: CSP must allow `worker-src blob:` (and possibly `script-src blob:` for module workers) and runtime policy must enable `allowBlobWorkers`.
  - Production: HTTPS is enforced for workerUrl.

- require + Blob not usable
  - Behavior: Library verifies the bytes but instantiates Worker from the URL. A narrow TOCTOU window remains between fetch and instantiation.
  - Recommendation: Enable Blob workers (CSP + runtime policy). Alternatively, ensure workers are served as immutable assets with CI-generated hashes.

- compute
  - Behavior: In dev, allowed. In production, blocked unless BOTH `setRuntimePolicy({ allowComputeIntegrityInProductionDefault: true })` AND per-call `allowComputeIntegrityInProduction: true` are set.
  - If Blob is enabled, the Worker will be created from a Blob of the verified bytes to eliminate TOCTOU.

## Error Codes

Security Kit surfaces consistent error codes via `SecurityKitError`. Some important ones:

- `E_INTEGRITY_REQUIRED` — `compute` is forbidden in production without explicit policy overrides.
- `E_BLOB_FORBIDDEN` — Blob workers are disabled by runtime policy.
- `E_CSP_BLOCKED` — Blob worker creation failed due to CSP or browser restrictions.
- `E_SIGNATURE_MISMATCH` — Worker script hash mismatch.
- `E_PAYLOAD_SIZE` — Canonical payload exceeded the configured maximum length.
- `E_CONFIG` — Configuration-related errors.

## Migration Notes

If you previously relied on `integrity: "compute"` being the default, you must now either:

1. Provide `expectedWorkerScriptHash` and use `integrity: "require"`, or
2. Explicitly pass `integrity: "compute"` and opt-in via `setRuntimePolicy({ allowComputeIntegrityInProductionDefault: true })` and per-call `allowComputeIntegrityInProduction: true` (both required for production), or
3. Enable `allowBlobWorkers` in development to let the library create Workers from verified blobs and avoid TOCTOU.

## Troubleshooting

- `Worker script integrity mismatch`: verify the `expectedWorkerScriptHash` was computed from the deployed worker file and is base64-encoded sha-256.
- `Blob worker creation failed (CSP?)`: check your CSP headers for `worker-src` or `script-src` restrictions.
- `compute not allowed in production`: set `allowComputeIntegrityInProduction` per-call and/or set the global policy, understanding the risks.

## Tests & CI

The repository includes tests that verify: handshake, rate-limiting fast path, Blob worker cache behavior, and server verification rules. Add CI to compute and store `expectedWorkerScriptHash` during build if you adopt `integrity: "require"`.

---

If you'd like, I can expand this into a full `docs/Integrity + Blob Worker Guide.md` with CI scripts and example GitHub Actions that compute the worker hash at build time and inject it into `expectedWorkerScriptHash` values during deployment.
