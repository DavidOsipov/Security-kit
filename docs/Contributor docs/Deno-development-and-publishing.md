# Deno Development and npm Publishing Guide for Security-kit

This guide explains how to use Deno effectively while developing in this repository and how to produce a bundle suitable for publishing to npm. It is grounded in Deno’s official documentation and tailored for this project’s security and zero-dependency goals.

- Audience: contributors to `@david-osipov/security-kit`
- Goals: reproducible dev flow with Deno, cross-runtime verification, and secure build artifacts for npm
- References: Deno official docs (configuration, tasks, permissions, testing, npm & Node interop, JSR)

---

## 1) Prerequisites

- Install Deno via the official installer (recommended by Deno):
  - Linux/macOS: `curl -fsSL https://deno.land/install.sh | sh`
  - Alternatively see: https://docs.deno.com/runtime/fundamentals/installation/
- Ensure Node.js LTS is installed for the existing npm build/test flow (tsup, Vitest).
- From repo root, you can verify:
  - `deno --version`
  - `node -v` and `npm -v`

Tip: Keep Deno up to date:
- `deno upgrade` (see docs: “nvm / n / fnm -> deno upgrade”).

---

## 2) Project Layout and Deno config

This repo remains Node-first for publishing to npm, while adding Deno support for local development and CI validation. The `deno.jsonc` configuration (kept at repo root) provides:

- Tasks for common actions (build, test)
- Lockfile enablement for reproducibility  
- JSR-compatible metadata (optional) and imports mappings when needed

**Migration Status**: Currently transitioning from `dist/`-based builds to hardened `@deno/dnt` builds:
- **Current**: Uses Node.js `tsup` to generate `dist/` directory for npm publishing
- **Target**: Uses Deno `@deno/dnt` to generate `npm/` directory for enhanced supply-chain security
- **Security Benefits**: Eliminates Node.js build-time dependencies, provides permission sandboxing, enables single-source-of-truth builds

Example settings pulled from Deno docs that we use or align with:
- Tasks: `deno task build`, `deno task test` (docs: configuration -> tasks)
- Lockfile: `lock: true` (or object with `path` and `frozen`) to ensure consistent deps
- Node interop when required: `nodeModulesDir: "auto"` for seamless npm resolution (not strictly required here since we don’t install npm deps for Deno tests)

Repository-aligned tasks (example):

```jsonc
{
  "tasks": {
    // Build the npm bundle using tsup (Node toolchain)
    "build": "npm run build",
    // Run Deno smoke tests against built dist/
    "test": "deno test -A deno_tests"
  },
  // Use a lock to make remote resolutions deterministic if imports are added later
  "lock": true
}
```

Note: This project aims for zero production dependencies and uses Web APIs; Deno can run our built ESM (`dist/index.mjs`) directly.

---

## 3) Day-to-day Development with Deno

Deno complements the existing Node workflow. Typical loop:

1. Build the library with npm (tsup):
   - `npm run build`
2. Run Deno smoke tests:
   - `deno task test`

You can also use Deno’s tooling locally:
- Format: `deno fmt`
- Lint: `deno lint`
- Type-check: `deno check src/**/*.ts`
- Benchmarks: `deno bench` (optional)

Permissions model: By default Deno is sandboxed. Use flags when needed (e.g., `-A` for all permissions in local smoke tests). Keep least privilege in CI and scripts when possible.

Caching and lockfiles:
- Deno caches remote modules automatically; we recommend keeping `deno.lock` under version control if we begin using remote `jsr:` or `npm:` imports via `imports` map.
- Use a frozen lock to ensure consistency in CI (`lock.frozen: true`).

Vendorizing (when using remote imports):
- This project avoids remote imports for production code. If you temporarily add remote modules for tooling/demos, prefer `jsr:` over raw `https:`.
- For absolute reproducibility, you can vendor them into the repo: `deno vendor <entry.ts>` (docs: modules -> vendor). This writes a `vendor/` directory and an import map so tests can run offline and deterministically.
- Review and commit vendor output only if it serves our security goals; otherwise, keep using `jsr:` with a frozen `deno.lock`.

---

## 4) Testing under Deno

- Tests live under `deno_tests/` and import the built ESM artifacts from `dist/`.
- Run: `deno test -A deno_tests` or simply `deno task test`.
- Use standard library assertions: `jsr:@std/assert` (mapped automatically by Deno when added via `deno add` or declared in `deno.json`).

Minimal example (from this repo):
- Asserting `generateSecureId(32)` length and `generateSecureUUID()` format.

Why test Deno separately?
- Independent runtime validation reduces supply-chain risk and proves cross-runtime portability of our hardened APIs.

Security-kit hardening callouts for tests:
- Never use `Math.random()` or ad-hoc crypto in tests; always exercise library APIs.
- Avoid bypassing `secureCompareAsync` when comparing secrets.
- Do not introduce network or filesystem permissions unless strictly needed; prefer `--allow-read` with a narrow path over `-A` in CI.

---

## 5) Node and npm Interop

Deno has native `npm:` and `node:` specifier support:
- Import npm packages directly (if ever needed): `import chalk from "npm:chalk@5"`
- Use Node built-ins explicitly: `import { Buffer } from "node:buffer"`
- If a `node_modules` directory is needed for certain workflows, set `nodeModulesDir: "auto"` in `deno.json`. This project generally avoids this to keep the dependency surface minimal.

Executing package.json scripts via Deno tasks:
- Deno can run `package.json` scripts with `deno task <name>` if configured, but we prefer explicit separation: `npm run` for Node-side tasks, `deno task` for Deno-side validation.

---

## 6) JSR Basics (Optional)

JSR is an open registry for JS/TS packages that Deno works with natively. If we decide to publish to JSR in addition to npm:

- Add required fields in `deno.json`:
  ```json
  {
    "name": "@scope/package-name",
    "version": "x.y.z",
    "exports": "./mod.ts"
  }
  ```
- Dry-run publish: `deno publish --dry-run`
- Real publish: `deno publish`

We currently map Deno tests to the built `dist` output for minimal churn. A future refactor may switch to source-first JSR exports or use `dnt` to generate npm artifacts from a single Deno source of truth.

---

## 7) Producing an npm Bundle (Current Path)

Our npm bundle is built with tsup and verified by Vitest. To ensure Deno parity before publishing to npm:

1. Clean, build and test on Node:
   - `npm run clean && npm run build && npm test`
2. Run the Deno smoke tests against `dist/`:
   - `deno task test`
3. If all green, proceed to npm publish process as usual (CI or manual):
   - Make sure package.json version is bumped and changelog updated
   - `npm publish --access public` (or CI workflow)

Security posture:
- Keep zero prod deps.
- Enforce typed errors, parameter validation, and constant-time comparisons per project constitutions.
- Prefer Deno’s sandboxing for local demos and scripts; grant least privileges.

Supply-chain hygiene:
- Use `deno.lock` (or frozen lock in CI) if `imports` are introduced.
- Avoid pulling code via `https:` URLs; prefer `jsr:` or vendored sources for auditability.
- Ensure `dist/` is built fresh in CI from a clean checkout; do not publish local-only changes.

---

## 8) Alternative: Deno-first source → npm via dnt (Future Option)

If we want to make Deno the single source and generate npm-compatible artifacts automatically, consider `deno_dnt`:
- `dnt` transpiles Deno modules (TS/ESM) into npm packages (CJS/ESM), handling shims for Node when required.
- Typical flow:
  - Author source as `.ts` with web-standard APIs
  - Use `dnt` in a build script to produce `npm/` publish directory
  - Publish that directory to npm

We have not adopted this yet to minimize change. Evaluate if consolidating builds improves security and maintenance.

---

## 9) CI Integration

- A dedicated CI job runs on Linux with the official `setup-deno` action and runs:
  - `npm ci && npm run build`
  - `deno task test`
- Keep CI least-privilege: only `-A` where necessary for tests that need net/fs; otherwise specify granular flags.
- Consider adding a JSR publish workflow (OIDC) in the future, and npm publish gate that requires both Node and Deno checks to pass.

---

## 10) Troubleshooting

- `Module not found` in Deno tests:
  - Ensure you built first: `npm run build` so `dist/` exists
  - Verify import path in `deno_tests/*` points to `../dist/index.mjs`
- Lint or fmt discrepancies:
  - Run `deno fmt` and `deno lint` locally; Deno and ESLint/Prettier may differ slightly. Prefer the repository’s primary tooling for source, and use Deno tools for tests/scripts.
- Permissions errors:
  - Add the minimum flags to `deno test` (e.g., `--allow-read` if reading files). Local smoke tests currently use `-A` for simplicity.

---

## 10) Hardened npm Build with @deno/dnt (Migration in Progress)

### Overview

This project is transitioning to use `@deno/dnt` for enhanced supply-chain security. The `dnt` (Deno-to-Node Transformation) tool generates npm-compatible packages from Deno TypeScript source, eliminating Node.js build-time dependencies.

### Current Build Process

```bash
# Run the hardened dnt build
deno run -A scripts/dnt-build.ts

# Output appears in npm/ directory (replaces dist/)
ls npm/  # Contains ESM, CJS, and TypeScript declarations
```

### Security Benefits

1. **Zero Build Dependencies**: No npm packages required during build process
2. **Permission Sandboxing**: Deno's explicit permissions prevent unauthorized access
3. **Single Source of Truth**: TypeScript source is directly transformed to npm artifacts
4. **Cross-Runtime Validation**: CI validates in both Deno and Node.js environments

### File Structure

```
npm/                    # dnt build output (replaces dist/)
├── esm/               # ES modules
├── script/            # CommonJS modules  
├── types/             # TypeScript declarations
├── package.json       # Generated package metadata
└── README.md          # Copied documentation
```

### Integration Status

- ✅ **dnt build script**: `scripts/dnt-build.ts` generates npm/ directory
- ✅ **Import fixes**: Source files updated with `.ts` extensions for Deno compatibility
- ✅ **Ignore patterns**: `npm/` excluded from Git and ESLint
- 🔄 **CI integration**: Updating workflows to use npm/ output
- 🔄 **Type definitions**: Resolving global type compatibility issues
- ⏳ **Full migration**: Complete transition from dist/ to npm/ workflow

### Migration Notes

- The `npm/` directory maintains full compatibility with existing package.json exports
- All entry points (main, worker, server, test-internals) are preserved
- TypeScript strict mode and security patterns remain unchanged
- No breaking changes for npm package consumers

## 11) Contributor Checklists

Before pushing:
- Node: `npm run build` + `npm test` pass
- Deno: `deno task test` passes
- No unexpected changes in `deno.lock` (if present) and no unpinned remote imports

Before publishing to npm:
- All CI checks green (Node + Deno)
- Version bumped, changelog updated
- Dist contains ESM/CJS + types and matches commits

---

## 12) References

- Deno configuration & tasks: https://docs.deno.com/runtime/fundamentals/configuration/
- Testing: https://docs.deno.com/runtime/fundamentals/testing/
- Node & npm interop: https://docs.deno.com/runtime/fundamentals/node/
- Import maps (`imports`): https://docs.deno.com/runtime/fundamentals/modules/
- Workspaces: https://docs.deno.com/runtime/fundamentals/workspaces/
- Publish to JSR: https://docs.deno.com/runtime/reference/cli/publish/
- CLI reference: https://docs.deno.com/runtime/reference/cli/
