Contributor Documentation — Security Kit

Welcome! This document provides guidelines for contributors who want to help improve the Security Kit project.

## Core principles

The project follows four founding pillars:

1. Zero Trust & Verifiable Security
2. Hardened Simplicity & Performance
3. Ergonomic & Pitfall-Free API Design
4. Absolute Testability & Provable Correctness

See `docs/Constitutions/` for the authoritative documents that govern architecture and testing expectations.

## Repository layout

Key folders:

- `src/` — TypeScript source code. All runtime code must be in TypeScript.
- `tests/` — Vitest test suites, mirrored structure to `src/`.
- `docs/` — Documentation, including these contributor and user docs.
- `benchmarks/` — Tinybench and benchmark harnesses.
- `scripts/` — Helper scripts used in CI and testing.

## Developer prerequisites

- Node.js >= 18.18.0
- npm
- TypeScript knowledge (strict mode)
- Familiarity with Web Crypto API recommended

## Local development

Install dev dependencies and run tests:

```bash
npm ci
npm run typecheck
npm run lint
npm run test:unit
```

## Build

To build the compiled bundles for distribution:

```bash
npm run build
```

## Testing philosophy

- Every new feature must include comprehensive unit tests under `tests/` mirroring `src/` paths.
- Adversarial tests are required for functions that process untrusted input (prototype pollution payloads, malformed Unicode, etc.).
- Mutation testing and performance tests are strongly encouraged (see `docs/The Official Testing & Quality Assurance Constitution.md`).

## Style & linting

The repository enforces strict ESLint rules with `eslint.config.js` and TypeScript compiler settings in `tsconfig.json`. Run `npm run lint` and `npm run typecheck` before opening PRs.

## Contributing workflow

1. Fork the repository and create a feature branch.
2. Run the unit tests and ensure everything passes.
3. Open a pull request describing the change, security considerations, and any potential breaking behavior.

## Security review process

- Security-related changes must reference the relevant pillar and include security tests.
- For crypto changes, include a rationale and references to standards (e.g., Web Crypto API guidance).

## Testing & CI

The project uses Vitest. For local test runs:

```bash
# run all tests
npm run test

# run security tests only
npm run test:security
```

Before merging a PR, ensure:

- `npm run typecheck` passes
- `npm run lint` passes
- `npm run test` passes

## Contact

If you have questions, open an issue or reach out via PR comments. The maintainers will triage and respond.
