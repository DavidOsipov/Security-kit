CONTRIBUTING.md — How to contribute to Security Kit

Thanks for wanting to contribute! This guide explains the expectations and workflow for code contributions.

## Before you start

- Read `docs/Constitutions/` to understand the project's security and testing expectations.
- Check open issues and PRs to avoid duplicating work.

## Creating a contribution

1. Fork and branch:
   - `git checkout -b feature/your-change`
2. Implement your change in `src/` (TypeScript only).
3. Add tests under `tests/` mirroring the `src/` path.
4. Run:
   - `npm run typecheck`
   - `npm run lint`
   - `npm run test`
5. Commit and open a PR describing what you changed and why.

## PR checklist

- Relevant tests added and passing.
- No new linter or type errors.
- Security rationale included for any behavior changes.
- Performance considerations discussed for expensive operations.

## Review and merging

- At least one maintainer approval required for non-trivial changes.
- Security-sensitive changes may require additional reviewers.

## Code of conduct

Follow the project's `CODE_OF_CONDUCT.md`.
