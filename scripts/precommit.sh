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
  npx lint-staged || { echo "lint-staged reported issues. Aborting commit."; exit 1; }
else
  echo "npx not available; skipping lint-staged."
fi

echo "pre-commit checks passed."
