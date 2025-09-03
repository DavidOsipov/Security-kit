# CodeQL Analysis Configuration and Suppressions

This document explains the CodeQL configuration for the `@david-osipov/security-kit` repository and why certain directories and patterns are excluded from security analysis.

## Background

The Security-Kit library implements a Zero Trust security model with extensive adversarial testing. The test suite intentionally includes:

- **Prototype pollution payloads** in `tests/unit/fuzz.prototype-pollution.test.ts` and `tests/unit/canonical.fuzz.spec.ts`
- **XSS attack vectors** in `tests/payloads/xss-payload-list.txt` 
- **Malicious JSON payloads** like `JSON.parse('{"constructor": {"prototype": {"isPolluted": true}}}')`
- **DoS attack simulations** and **timing attack vectors**
- **Path traversal attempts** in URL security tests

These payloads are intentionally malicious and designed to verify that the security library properly defends against them.

## Configuration Strategy

The CodeQL configuration (`.github/codeql/codeql-config.yml`) excludes test directories from security analysis while maintaining full coverage of production code:

### Excluded Paths
- `tests/` - Contains adversarial test payloads
- `demo/` - Contains example code that may demonstrate vulnerabilities  
- `scripts/` and `tools/` - Build and development utilities
- All `*.test.ts`, `*.test.js`, `*.spec.ts`, `*.spec.js` files

### Included Paths  
- `src/` - Core library production code
- `server/` - Server-side utilities production code

### Query Configuration
- Uses `security-extended` and `security-and-quality` query suites
- Excludes specific false positive patterns that are safe in this controlled context

## Why This Is Safe

1. **Separation of Concerns**: Test code containing malicious payloads is never shipped to consumers - only the `src/` and `server/` directories are included in the published package exports.

2. **Intentional Security Testing**: The "malicious" code in tests is specifically designed to verify that the production library code properly defends against attacks.

3. **Comprehensive Production Coverage**: All production code in `src/` and `server/` remains under full CodeQL analysis.

4. **Defense in Depth**: The library implements multiple security layers:
   - Input validation and sanitization
   - Constant-time comparison functions  
   - Prototype pollution prevention
   - Memory hygiene with `secureWipe()`
   - State machine integrity with `sealSecurityKit()`

## Auditing Guidance

When reviewing CodeQL results, verify:

1. **No production code suppressions**: The `src/` and `server/` directories should have zero suppressions or exclusions.

2. **Test isolation**: Malicious payloads in tests should be contained within test functions and not leak into production code paths.

3. **Package exports**: Verify that `package.json` exports only include production code, never test utilities.

4. **Security Constitution compliance**: All production code should adhere to the four foundational pillars defined in `docs/Security Constitution.md`.

## Alternative Approaches Considered

1. **Inline suppressions**: Adding `// codeql-disable` comments throughout test files was rejected as it would clutter the adversarial tests and make them harder to maintain.

2. **Per-file configuration**: Creating individual `.qlpack.yml` files was rejected as too complex for the maintenance overhead.

3. **Separate test scanning**: Running CodeQL only on production code was chosen as the optimal balance of security coverage and noise reduction.

If you prefer additional granular controls or have specific CodeQL rules that should be enabled for test files, this configuration can be extended while preserving the core exclusion strategy.