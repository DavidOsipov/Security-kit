# Enforcing CI Guard in GitHub Branch Protection

To ensure the no-blob-fallback guard is always run on PRs and cannot be bypassed, add the `check-no-blob-fallback` workflow as a required status check in GitHub branch protection for `main`.

Steps:

1. Go to your repository on GitHub and open `Settings` → `Branches` → `Branch protection rules`.
2. Click `Add rule` (or edit the existing `main` rule).
3. Under `Protect matching branches`, ensure the branch pattern is `main`.
4. Enable `Require status checks to pass before merging`.
5. In the list of status checks, add the workflow job name:
   - `CI — no blob fallback / check-no-blob-fallback` (the exact name shown in the Actions UI may vary slightly; choose the job that corresponds to `.github/workflows/ci-no-blob-fallback.yml`).
6. Optionally enable `Require branches to be up to date before merging` to ensure the check runs on the latest branch state.
7. Save changes.

Notes:
- Once enabled, any PRs that contain forbidden patterns will fail the status check and cannot be merged until fixed.
- Make sure the workflow is allowed to run for pull requests from forks if you accept external contributions (see `Workflow permissions` in the repository Settings).

### Troubleshooting guard failures

If the guard fails locally or in CI, here are the common causes and fixes:

- Stale git index entry (tracked-but-deleted file):

   Sometimes a file is removed from the working tree but still tracked in Git's index (this can happen when a file was removed locally but the removal wasn't committed). In that case `git ls-files` or `git grep` may still report the path and the guard can raise an error or locate a forbidden pattern in the stale entry.

   Fix: remove the stale entry from Git's index and commit the change:

   ```bash
   git rm --cached src/api-signing.ts
   git commit -m "Remove stale tracked file entry: src/api-signing.ts"
   ```

- Forbidden pattern match: the guard scans for specific source patterns that indicate an embedded blob fallback. If your PR intentionally adds similar code for a dev-only purpose, instead consider putting it behind a clear opt-in and documenting why it's safe. Otherwise remove the pattern and re-run the guard.

- Node deprecation warnings in CI: after moving the guard to use `git grep` we avoid most filesystem APIs that trigger Node deprecation warnings. If you still see a deprecation warning in CI, it's safe to inspect the trace by running with `--trace-deprecation` locally to find the origin. Do not suppress warnings globally in CI; prefer addressing the underlying source.

### Developer workflow (quick)

1. Run the guard locally before push:

```bash
npx ts-node-esm ./scripts/ci-guard-no-blob-fallback.ts
```

2. If the guard fails because of a stale tracked file, run the `git rm --cached` command shown above and commit the removal.

3. Push and open a PR. The `CI — no blob fallback` check will run automatically.

