Testing Guide — Security Kit

This document describes the testing requirements and how to run tests locally.

## Test runner and environment

- Vitest is the test runner. The test suite is split between `tests/unit`, `tests/security`, `tests/integration`, and `tests/performance`.
- Some performance tests are intentionally skipped in CI; run them locally only when benchmarking.

## Running tests

Install dev dependencies and run tests:

```bash
npm ci
npm run test:unit
npm run test:security
npm run test:integration
```

Running all tests (may be slow):

```bash
npm run test
```

## Writing tests

- Mirror `src/` directory structure in `tests/`.
- For security-sensitive functions, include adversarial test cases such as:
  - Prototype pollution payloads: `{ "__proto__": { "polluted": true } }`
  - Unicode normalization edge cases (NFKC/NFD combos)
  - Long/large inputs for DoS protection assertions
- Tests should assert typed errors where applicable (e.g., `InvalidParameterError`).

## Mutation testing and fuzzing

See `docs/The Official Testing & Quality Assurance Constitution.md` for guidance on mutation tests and fuzz harnesses. This project expects high mutation test coverage for security-critical code.
