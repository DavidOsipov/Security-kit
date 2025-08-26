# Secure API Signing (client-worker-server)

This document describes the Secure API Signing feature in this repository. It explains the three main components:

- Client-side signer API: `src/secure-api-signer.ts`
- Worker implementation: `src/worker/signing-worker.ts`
- Server-side verifier: `server/verify-api-request-signature.ts`

It covers message shapes, usage examples, security hardenings, deployment notes, and troubleshooting.

## Overview

The feature implements an HMAC-SHA256-based signing flow where a client holds a secret (opaque bytes) and signs request payloads in a dedicated worker to avoid keeping the secret reachable on the main thread. The signed payload includes a nonce and timestamp for replay protection. The server verifies signatures, enforces a timestamp window, and tracks used nonces per key id (kid).

## Files

- `src/secure-api-signer.ts` — a small library that instantiates a Worker, transfers the secret as a transferable ArrayBuffer to the worker, and offers a `sign(payload)` method that returns `{ signature, nonce, timestamp, kid }`.
- `src/worker/signing-worker.ts` — the canonical worker script. It imports the transferred secret into a SubtleCrypto HMAC key and answers `sign` requests. It contains several hardenings: validation, payload limits, concurrency caps, rate limiting, and optional dev logging.
- `server/verify-api-request-signature.ts` — server-side verifier that canonicalizes the message, enforces timestamp skew and nonce uniqueness per `kid`, computes HMAC-SHA256 server-side (SubtleCrypto when available or Node fallback), and performs a constant-time compare.

## Protocol / Message Formats

Client → Worker messages

- Init message (transferred ArrayBuffer secret):

```
{ type: 'init', secretBuffer: ArrayBuffer, kid?: string, workerOptions?: { rateLimitPerMinute?: number, dev?: boolean } }
```

- Sign request:

```
{ type: 'sign', requestId: number, payload: string, nonce: string, timestamp: number }
```

- Destroy worker request:

```
{ type: 'destroy' }
```

Worker → Client messages

- Initialized:

```
{ type: 'initialized' }
```

- Signed result:

```
{ type: 'signed', requestId: number, signature: string } // signature is base64
```

- Error (per-request or init-level):

```
{ type: 'error', requestId?: number, reason: string }
```

- Destroyed notification:

```
{ type: 'destroyed' }
```

Server verification input (server API):

```
{ secret, payload, nonce, timestamp, signatureBase64, kid, method?, path?, bodyBytes? }
```

Refer to `server/verify-api-request-signature.ts` for the exact `VerifyExtendedInput` TypeScript type.

## Examples

Client (browser, bundler-friendly):

```ts
import { SecureApiSigner } from './src/secure-api-signer';

const secret = /* Uint8Array or base64 string from server */;
const signer = await SecureApiSigner.create({ secret, workerUrl: new URL('./worker/signing-worker.ts', import.meta.url), kid: 'key-1' });

const result = await signer.sign({ foo: 'bar' });
// result => { signature: '...', nonce: '...', timestamp: 12345, kid: 'key-1', algorithm: 'HMAC-SHA256' }

// Send to server in your request headers/body
```

Server (Node/edge):

```ts
import { verifyApiRequestSignature } from '../server/verify-api-request-signature';

const ok = await verifyApiRequestSignature({
  secret: serverKnownSecretForKid, // ArrayBuffer/Uint8Array or base64
  payload: requestBodyPayload,
  nonce: requestNonce,
  timestamp: requestTimestamp,
  signatureBase64: requestSignature,
  kid: requestKid,
  method: request.method,
  path: request.path,
  bodyBytes: requestBodyBytes // optional
});

if (!ok) return respondWithUnauthorized();

// proceed
```

## Security considerations

- Secrets transferred to the worker are sent as transferable ArrayBuffer and the main-thread copy is neutered; keep secrets short-lived and provisioned via a secure channel.
- The server-side verifier requires `kid` to prevent cross-key nonce collisions; avoid using a single placeholder `kid` in production.
- Worker enforces a payload character limit and rate limiting to mitigate resource exhaustion.
- The server uses timestamp skew validation (default ±2 minutes) and per-kid nonce tracking to reduce replay risk.

## Operational notes

- Bundlers: `new URL('./worker/signing-worker.ts', import.meta.url)` is the recommended way to let bundlers emit a separate worker asset. Alternatively pass `workerUrl` explicitly pointing to a hosted worker file.
- Module vs classic worker: pass `useModuleWorker` to `SecureApiSigner.create()` if you need `type: 'module'`.
- Nonce store: the `server/verify-api-request-signature.ts` file includes an `InMemoryNonceStore` demonstration implementation (not for production). For production use a distributed store (Redis) so replay protection works across server instances.

## Troubleshooting

- If signature verification fails, check canonicalization details (method/path/bodyHash/payload/kid) match between client and server.
- If worker initialization fails, ensure your bundler emits the worker asset and the `workerUrl` is reachable.
- If rate limiting triggers in the worker, adjust `workerOptions` during `init` or reduce client request rate.

---

This document is generated automatically. If you'd like additional examples, test stubs, or a migration guide, tell me where to add them.

## Usage & Fallback

The library prefers bundler-friendly worker emission (recommended):

- Pass an explicit worker URL:

```ts
const signer = await SecureApiSigner.create({ secret, workerUrl: new URL('./worker/signing-worker.ts', import.meta.url) });
```

- Or rely on bundler rewriting `new URL('./worker/signing-worker.ts', import.meta.url)` which many bundlers (Vite, Rollup) support.

Worker resolution and strict policy

- This library no longer supports an embedded-blob fallback. If no `workerUrl` is provided and automatic bundler-friendly resolution via `new URL('./worker/signing-worker.ts', import.meta.url)` fails, `SecureApiSigner.create()` will throw and ask consumers to pass an explicit `workerUrl`.

- This decision intentionally avoids blob: URL usage in consumers' applications and prevents accidental CSP weakening or differences between dev/test and production environments.

Recommended approaches:

- Prefer bundler emission: use `new URL('./worker/signing-worker.ts', import.meta.url)` and let your bundler (Vite, Rollup, etc.) emit the worker asset.
- Or serve/host the worker as a separate file and pass its URL via `workerUrl` to `SecureApiSigner.create()`.

