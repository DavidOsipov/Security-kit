# Worker concurrency & testing patterns

This document explains the concurrency model implemented in `src/worker/signing-worker.ts` and the testing patterns used in `tests/unit/signing-worker.test.ts`.

It is intended for maintainers and contributors who need to understand, extend, or debug the worker's concurrency and rate-limiting behavior and the test harness that verifies it.

## Contract (inputs / outputs / errors)

- Inputs (messages posted to worker):
  - `init` - { type: 'init', secretBuffer: ArrayBuffer, workerOptions?: object }
  - `handshake` - { type: 'handshake', nonce: string } (reply via MessagePort)
  - `sign` - { type: 'sign', requestId: number, canonical: string } (reply via MessagePort or `postMessage`)
  - `destroy` - { type: 'destroy' }

- Outputs (worker responses):
  - `{ type: 'initialized' }`
  - `{ type: 'signed', requestId, signature }`
  - `{ type: 'error', requestId?, reason }`
  - `{ type: 'destroyed' }`

- Error modes:
  - `missing-secret`, `invalid-params`, `canonical-too-large`, `rate-limit-exceeded`, `worker-overloaded`, `worker-shutting-down`, `sign-failed`, `handshake-failed`, `already-initialized`, `worker-exception`.

## High-level concurrency model

- The worker uses an internal `WorkerState` object managed by a small state manager (closure) that is mutated via `updateState()` and read via `getCurrent()`.
- Concurrency and in-flight operations are tracked using `pendingCount` and `maxConcurrentSigning` in state.
- The worker reserves a concurrency slot synchronously (no awaits) using `tryReserveSlotInline()` to avoid race conditions when multiple sign messages arrive nearly simultaneously.
- After the synchronous reservation, the handler yields a microtask (`await Promise.resolve()`) to let test harness and runtime visibility settle before performing rate-limited or async work.
- Slots are released in a `finally` block after the sign operation completes or fails.

## Rate limiting

- Token bucket model using integer arithmetic to avoid float-drift.
- Configurable via `workerOptions.rateLimitPerMinute` and optional `rateLimitBurst`.
- Tokens are refilled on demand using `refillTokens()`.
- `enforceRateLimit()` consumes a token if available; otherwise responds with `rate-limit-exceeded`.

## Init handling

- `handleInitMessage()` sets an `initializing` guard in state to prevent duplicate/concurrent initialization attempts. If `initialized` or `initializing` is true, the worker responds with `already-initialized`.
- The worker stores a locked inbound origin on first successful init for subsequent origin verification.

## Key functions and where to find them

- `tryReserveSlotInline()` — synchronously checks `pendingCount` and increments if under `maxConcurrentSigning`.
- `handleSignRequest()` — main sign handler; performs validation, synchronous reservation, microtask yield, rate-limit enforcement, `doSign()`, and finally releases the slot.
- `enforceRateLimit()` & `refillTokens()` — token-bucket logic.
- `handleInitMessage()` — init guard and importKey.

## Testing patterns used in `tests/unit/signing-worker.test.ts`

- The file sets up a mocked worker-like environment for deterministic unit tests:
  - `vi.stubGlobal('self')` and `vi.stubGlobal('postMessage')` to capture `postMessage` calls.
  - A mocked `crypto.subtle` object with `sign` and `importKey` spies that tests control.
  - `createSecurePostMessageListener` from `src/postMessage` is mocked to capture the message listener callback before importing the worker module.
  - `capturedMessageListener` is used to call into the worker as if messages were posted to it.

- Important test harness details:
  - Tests call `setupWorkerMocks()` to reset mocks and module registry (`vi.resetModules()`), then re-import the worker module so the top-level listener registration runs in the test-controlled environment.
  - `waitForListener()` waits briefly for the test-side mocked `createSecurePostMessageListener` to capture the listener.
  - `MockMessageEvent` and `MockMessagePort` implement minimal behavior to emulate `MessageEvent` and `MessagePort` semantics for reply ports.

- Avoiding flaky timing:
  - Where tests need to simulate concurrent messages, they intentionally _do not await_ the first handler and instead call the listener and yield a microtask (`await Promise.resolve()`) or poll briefly for expected `postMessage` calls. This reliably reproduces race windows in Node/Vitest test environment.
  - Long-running crypto operations are stubbed using `mockSign.mockImplementation(async () => { await new Promise(r => setTimeout(r, 50)); return new ArrayBuffer(0); });` to force overlap.

## Recipes / Examples

- Reproduce concurrency limit rejection:
  1. Set `workerOptions.maxConcurrentSigning` to `1` in `init`.
  2. Start a `sign` request whose mocked `crypto.subtle.sign` delays (e.g., `setTimeout` 50ms).
  3. Immediately send a second `sign` request and assert it responds with `{ type: 'error', reason: 'worker-overloaded' }`.

- Reproduce rate limit rejection:
  1. Set `workerOptions.rateLimitPerMinute` to `1` in `init`.
  2. Fire a sign request and wait for it to complete.
  3. Send another sign request and assert `{ type: 'error', reason: 'rate-limit-exceeded' }`.

## Troubleshooting tips

- If tests say the listener wasn't captured:
  - Ensure `createSecurePostMessageListener` is mocked and sets `capturedMessageListener` before importing the worker module.
  - Use `waitForListener()` to allow the test harness to discover the installed listener.

- If rate-limit/concurrency tests are flaky:
  - Make the first `sign` call deliberately slow in the mock (`setTimeout`) to ensure overlap.
  - Use microtask yields (`await Promise.resolve()`) or short polling loops in tests to wait for expected `postMessage` side effects.

## Local commands

Run the signing-worker test file only:

```bash
npx vitest run tests/unit/signing-worker.test.ts
```

Run a single test by name (example):

```bash
npx vitest run tests/unit/signing-worker.test.ts -t "enforces concurrency limits"
```

## Owner / Contact

- Owner: Maintainers of the `Security-kit` repository.
- For questions: open an issue or contact the commit author who made the recent changes.

## Changelog

- 2025-09-01: Created by assistant — initial draft documenting concurrency & testing patterns.
