This folder contains the project's test suites.

New tests added:

- `tests/unit/crypto.comprehensive.spec.ts` — Additional coverage for crypto lifecycle:
  - synchronous API behavior (ensureCryptoSync)
  - sealing behavior and state transitions
  - concurrent `secureRandomBytes` calls
  - internal test utilities and cached crypto inspection
  - strict parameter validation for `secureRandomBytes`

Run these tests with the project's normal test runner. Example (from project root):

```bash
# runs all tests (may be slow)
pnpm test

# run only the new file with vitest
npx vitest run tests/unit/crypto.comprehensive.spec.ts
```
