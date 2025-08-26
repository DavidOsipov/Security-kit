import { test } from 'vitest';

// Placeholder tests for SecureApiSigner. The full behavior depends on
// Worker, fetch, and crypto.subtle; those are better tested with
// integration tests that stub/monkeypatch Worker and fetch.

test.skip('secure-api-signer: create() throws on invalid workerUrl (TODO)', () => {
  // TODO: unit test normalizeAndValidateWorkerUrl and create path validations
});

test.skip('secure-api-signer: sign() integrates with worker (TODO)', () => {
  // TODO: stub Worker and test sign happy path and timeouts
});
