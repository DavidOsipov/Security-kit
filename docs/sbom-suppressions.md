# SBOM Script Static Analyzer Suppressions

This document explains why certain static analyzer warnings (Sonar, CodeQL, ESLint security plugin) in `scripts/generate-sbom.ts` are safe to suppress.

## Background
The SBOM generator needs to operate on user-supplied paths (package path, output path) while remaining secure. To defend against path traversal and symlink attacks the script:

- Resolves absolute paths via `path.resolve` and `fs.realpathSync` when possible.
- Uses `resolveAndValidateUserPath(...)` to canonicalize and ensure any user-supplied path is contained within an allowed base (repository root or a caller-supplied directory).
- Uses `assertPathAllowed(...)` which resolves parent directories and ensures containment against a realpath-resolved allowed base.
- Performs explicit checks before writing (atomic write: temp file then rename) and validates that the temp path and final destination are inside the allowed base.

These runtime checks are conservative and intentionally designed to be recognized by reviewers and auditors even if automatic static analyzers flag non-literal fs calls.

## Suppressions added
The following suppressions were added with inline comments in the source:

- `security/detect-non-literal-fs-filename` (ESLint) — suppressed at read/write/rename points where the path is resolved and `assertPathAllowed` has been called immediately prior. Each suppression includes a short justification (e.g., "safePath resolved and asserted above").

- `NOSONAR` file-level comment — added to the top of `scripts/generate-sbom.ts` to indicate to Sonar that findings in this file are either false positives or intentionally mitigated by the validation code. The file-level note points to this document for rationale.

## Why this is safe
- The script never writes to arbitrary paths: `atomicWriteFileSync` ensures the temporary file and final destination are both under the allowed base; if not, the script throws and refuses to write.
- When reading paths for hashing, the script canonicalizes and asserts containment before calling `fs.readFileSync`.
- For non-existent targets (e.g., temp files), the script resolves the parent directory and validates containment before creating files.

## Auditing guidance
When reviewing these suppressions, verify the following:

1. `resolveAndValidateUserPath` and `assertPathAllowed` have not been changed to weaken validations.
2. Any call site that suppresses `security/detect-non-literal-fs-filename` should be accompanied by a short comment referencing the validation (the code includes these comments).
3. For additional assurance, consider adding unit tests that exercise attempts to escape the allowed base via symlinks or ../ sequences; the script already contains defensive logic to fail in those cases.

If you prefer stricter analyzer suppression (for example, CodeQL-specific annotations), we can add those as well while preserving the runtime validations.
