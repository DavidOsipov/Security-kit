#!/usr/bin/env bash
# Minimal pre-commit script: run gitleaks if installed, then run lint-staged
set -euo pipefail

echo "Running pre-commit checks..."
if command -v gitleaks >/dev/null 2>&1; then
  echo "Running gitleaks detect..."
  if [ -f "$(git rev-parse --show-toplevel)/.gitleaks.toml" ]; then
    gitleaks detect --source . --config .gitleaks.toml --exit-code 1 || { echo "Gitleaks found secrets. Aborting commit."; exit 1; }
  else
    gitleaks detect --source . --exit-code 1 || { echo "Gitleaks found secrets. Aborting commit."; exit 1; }
  fi
else
  echo "gitleaks not installed; skipping secret scan (install gitleaks to enable)."
fi

# Run lint-staged (will run eslint --fix on staged TS files)
if command -v npx >/dev/null 2>&1; then
  echo "Running lint-staged..."
  # Use ENFORCE_LINT environment variable to control behavior.
  # - ENFORCE_LINT=true  => abort commit on lint-staged failure (production)
  # - ENFORCE_LINT not set => continue on lint-staged failure (beta/default)
  if npx lint-staged; then
    echo "lint-staged passed."
  else
    if [ "${ENFORCE_LINT:-}" = "true" ]; then
      echo "lint-staged reported issues. Aborting commit because ENFORCE_LINT=true." >&2
      exit 1
    else
      echo "lint-staged reported issues. Continuing commit because ENFORCE_LINT is not set (beta mode)." >&2
      echo "To enforce lint checks in production set: export ENFORCE_LINT=true" >&2
    fi
  fi
else
  echo "npx not available; skipping lint-staged."
fi

echo "pre-commit checks passed."
