# Secure Startup and Capability Pattern

This document explains the secure startup and capability pattern used by the security-kit library. It documents the recommended initialization sequence, the semantics of "sealing" the kit, how to safely expose capabilities, and practical examples (server and worker). It also details migration notes, common pitfalls, and a checklist for application authors.

## Why this matters

security-kit aims to be used in hostile environments and by default enforces "secure by default" patterns (see the project's Constitutions). One key guard is that runtime configuration and capabilities must be established during application startup and then frozen (sealed) so that later code — including untrusted or less-trusted modules — can't escalate privileges by mutating configuration or adding secret-bearing capabilities.

## Goals

- Ensure initialization is deterministic and auditable.
- Make the default runtime safe for mixed-trust code: untrusted modules should not be able to mutate global configuration or gain access to secrets after startup.
- Provide ergonomic APIs for well-scoped capability handing and least-privilege design.
- Offer a concise checklist and examples showing common usage patterns.

## Core concepts

- "Kit" / "Security Kit": the runtime module exported by `src/index.ts` which wires together cryptographic helpers, cache primitives, and environment guards.
- "Seal": an operation that transitions the kit into a production-ready, immutable state. After sealing, most configuration mutation APIs throw `InvalidConfigurationError`.
- "Capability": a narrow, intentionally-limited object or function that grants access to a controlled action (for example, `signRequest`, `getSigningKey`, or `verifyNonce`). Capabilities should be created during startup and passed explicitly to modules that need them.
- "Least privilege": capabilities granted should have the minimal permissions necessary and should be passed to only the modules that require them.

## The secure startup pattern (recommended)

1. Bootstrap in a controlled entrypoint (typically the application's `main()` or server startup script).
2. Load required configuration and secrets only in the bootstrapper. Prefer environment variables or a secure secrets store. Validate and canonicalize configuration values immediately.
3. Create the minimal set of capabilities needed by your application. Each capability should be a narrow function or object with a small, well-typed surface.
4. Wire the capabilities into your HTTP handlers or worker bootstrap code by passing them explicitly (do not attach secrets to global objects, and avoid using `require()` inside untrusted code to fetch capabilities).
5. Call `sealSecurityKit()` (or the kit's seal function) after wiring is complete. This prevents later mutation and helps surface accidental late-time configuration changes.
6. Start accepting traffic or instantiate worker loops.

## Why the explicit seal() call?

- Transparency: Sealing is an explicit, observable transition point. In CI and audits you can assert that `sealSecurityKit()` is called during startup.
- Fail-safe: After sealing, operations that would expose or mutate secrets will fail fast with typed errors (e.g. `InvalidConfigurationError`).
- Testing: You can keep tests unsealed for dynamic setup, but production code should always seal early.

## Capabilities — design guidelines

- Keep them small: single-purpose functions or objects with one responsibility.
- Prefer function factories: instead of giving a module direct access to a secret key, give it `createSigner(scope)` which returns a signer that only signs that scope's payloads.
- Limit lifetime: where appropriate, create capabilities that auto-expire or are revoked by the kit's lifecycle hooks.
- Avoid returning raw `CryptoKey` objects from high-trust modules to untrusted code. If you must, wrap them in thin safe abstractions that restrict use and perform constant-time compare checks, input validation, and logging.

## Example: server startup (Node.js / TypeScript)

This example shows a minimal server bootstrap that creates a signing capability and a verifier capability, wires them to handlers, and then seals the kit.

// ...existing code...

1. Read configuration and secrets
   const SIGNING_KEY = loadSecret('API_SIGNING_KEY'); // secure fetch
   validateKeyFormat(SIGNING_KEY);

2. Build capabilities
   const signingCapability = createSigningCapability({ key: SIGNING_KEY, alg: 'HMAC-SHA256' });
   const verifyCapability = createVerifyCapability({ nonceStore: new InMemoryNonceStore() });

3. Wire to handlers
   const app = createHttpServer();
   app.post('/sign', (req, res) => {
   // pass only the narrow inputs needed
   const sig = signingCapability.sign({ method: req.method, path: req.path, body: req.body });
   res.send({ signature: sig });
   });

4. Seal
   sealSecurityKit();

5. Start server
   app.listen(PORT);

## Example: worker with limited capability

- Workers should not receive full secrets. Instead, create narrow handler functions during main/bootstrap and pass them the sealed capabilities.

const transformWorker = (readOnlyCache, signingCapability) => {
return async function onMessage(event) {
const { id, data } = event.data;
// use readOnlyCache.get(key) — this is a facade without mutators
const cached = readOnlyCache.get('some-key');
if (cached) return postMessage({ id, ok: true });

    const sig = await signingCapability.signPartial(data);
    postMessage({ id, sig });

};
};

// In bootstrap
const readOnlyCache = VerifiedByteCache.asReadOnly();
const signingCapability = createSigningCapability(...);
sealSecurityKit();
const workerHandler = transformWorker(readOnlyCache, signingCapability);
// register worker handler

## Sealing and tests

- Unit tests should avoid sealing by default so they can construct and tear down different configurations. For integration tests that simulate production, call `sealSecurityKit()` as part of test setup.
- For tests that need to mutate state after sealing, either create the kit in a child process or provide test-only helpers (kept out of production builds) to reset state.

## Migration notes for library consumers

- If your codebase currently reads secrets from globals at runtime, refactor to a single bootstrap module that reads secrets once and constructs capabilities.
- Replace direct usage of `crypto.getRandomValues()` and direct `CryptoKey` sharing with the kit's high-level helpers (see `src/crypto.ts`) to benefit from non-extractable keys and secure wiping.
- When adopting the read-only cache facade, change call sites that mutate cache to use an explicit, injected cache instance with limited permissions.

## Checklist for reviewers / auditors

- Is there a single bootstrap module that reads and validates secrets?
- Are capabilities created in the bootstrap and passed explicitly to code that needs them?
- Is `sealSecurityKit()` called before accepting external input?
- Do production codepaths avoid exposing raw keys or global mutable configuration objects?
- Do tests that require mutation run unsealed or in isolated processes?
- Are critical operations using constant-time compare and secureWipe on sensitive buffers?

## Common pitfalls

- Mutating a capability after passing it to untrusted code.
- Passing raw CryptoKey or exposing `Uint8Array` secrets without copying / wiping.
- Forgetting to seal in production code.
- Overly-broad capabilities that can be used for privilege escalation (for example, a generic "sign anything" function).

## Appendix: recommended helper signatures

- createSigningCapability(opts: { key: Uint8Array | CryptoKey, alg: 'HMAC-SHA256' | ... }): SigningCapability
- createVerifyCapability(opts: { nonceStore: INonceStore, maxSkewMs?: number }): VerifyCapability
- sealSecurityKit(): void

## Notes about this document

- This document is intended for application authors using security-kit. It's not a substitute for reading the project's Security Constitutions (see `docs/Constitutions`) which are the authoritative source.
- Keep this file near the user-facing docs to provide a concise, actionable guide for integrating the kit securely.
