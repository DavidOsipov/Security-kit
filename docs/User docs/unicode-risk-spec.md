# Unicode & Canonicalization Security Configuration Specification

> Scope: This document describes the security-focused configuration options introduced for Unicode normalization, canonicalization, and structural traversal hardening. It complements the Security Constitution and OWASP ASVS L3 alignment.

## Goals

1. Fail loud and early on anomalous Unicode / structural inputs.
2. Provide deterministic, testable hardening knobs with safe clamps.
3. Prevent performance-oriented downgrade attacks (normalization bombs, combining mark DoS, deep graph traversal, proxy trap stalls).
4. Preserve ergonomic defaults while enabling strict tuning in production.

## Unicode Security Config Keys

| Key | Type | Default | Purpose | Security Rationale |
|-----|------|---------|---------|--------------------|
| `maxCombiningRatio` | number (0,0.9] | 0.3 | Upper bound on fraction of combining marks within sufficiently long input | Mitigates rendering & normalization DoS; spoofing obfuscation |
| `minCombiningRatioScanLength` | integer ≥1 | 20 | Minimum length before ratio enforcement | Avoids false positives on short legitimate accented strings |
| `normalizationIdempotencyMode` | 'off' \| 'sample' \| 'always' | 'sample' | Controls idempotency verification after NFKC | Detects engine or polyfill anomalies; defense-in-depth |
| `normalizationIdempotencySampleRate` | int ≥1 | 64 | 1-in-N deterministic sampling when mode='sample' | Bounds cost while preserving anomaly detection | 
| `enableRiskScoring` | boolean | false | Enables cumulative soft risk scoring | Aggregates multiple sub-threshold signals; optional blocking |
| `riskWarnThreshold` | int | 40 | Emits dev warning when score ≥ threshold | Early operator visibility |
| `riskBlockThreshold` | int | 60 | Throws `SecurityValidationError` when exceeded | Fail-closed under multi-vector Unicode manipulation |
| `maxInputLength` | int | 2048 | Hard length cap (bytes/UTF-16 units) | DoS mitigation (CPU/memory) |
| `rejectIntroducedStructuralChars` | boolean | true | Block normalization-introduced delimiters | Prevent host/path/query smuggling via normalization |

### Combining Marks Enforcement
Two layers:
1. Per-base cap: `MAX_COMBINING_CHARS_PER_BASE` (5) – prevents local glyph stacking.
2. Global density ratio: configurable. Trigger emits metric `unicode.reject.combiningRatio`.

### Idempotency Verification Modes
- `off`: Skip second-pass check (performance priority).
- `sample`: Deterministic sampling: `(len ^ firstCodePoint) % sampleRate === 0`.
- `always`: Always verify (highest assurance, more cost on large inputs).

Failures throw `InvalidParameterError` with context-tagged message.

## Canonicalization (Structural) Config Keys

| Key | Type | Default | Purpose | Rationale |
|-----|------|---------|---------|-----------|
| `circularPolicy` | 'fail' \| 'annotate' | 'fail' | Behavior when a cycle is detected | Fail-loud default prevents ambiguous partial output |
| `traversalTimeBudgetMs` | number >0 | 25 | Wall-clock budget per canonicalization call | Halts pathological proxies / expensive getters |
| `maxDepth` | int | 256 | Depth budget (defense-in-depth) | Prevents deep nesting exhaustion |
| `maxTopLevelArrayLength` | int | 1,000,000 | Cap giant arrays | Memory/CPU bound control |
| `maxStringLengthBytes` | int | 10 MiB | Cap top-level string inputs | Prevents large payload amplification |

### Circular Handling
- `fail` (default): Throws `CanonicalizationTraversalError` immediately on cycle detection.
- `annotate`: Inserts `{ __circular: true }` sentinel objects (frozen arrays & objects preserved) and adds a non-enumerable `__circular` marker at top-level when any cycle present.

### Time Budget Enforcement
Traversal uses a timestamp deadline (`Date.now() + traversalTimeBudgetMs`). Exceeding budget throws `CanonicalizationTraversalError`. This guards against:
- Proxies with expensive `ownKeys` or `getOwnPropertyDescriptor` traps.
- Degenerate high fan-out graphs with adversarial accessor counts.

### Array Freezing & Detection
Canonicalized arrays are now `Object.freeze`d. Helper export: `isCanonicalArray(value)` returns true when value is a frozen array (post-canonicalization). This prevents downstream mutation attempts and enables consumer assertions.

## Logging Sanitization Changes
- Removed legacy DJB2 correlation hash (non-essential, potential micro-cost).
- Added run-length encoding collapse of `[CTRL]` and `[BIDI]` markers: large bursts become `[CTRL]xN` or `[BIDI]xN` reducing log amplification risk.

## Error Taxonomy (Additions)
| Error | Thrown When | Notes |
|-------|-------------|-------|
| `CanonicalizationDepthError` | Depth budget exceeded | Extends `InvalidParameterError` for stable handling |
| `CanonicalizationTraversalError` | Circular (policy=fail) or time budget exceeded | Explicit traversal failure classification |
| `SecurityValidationError` | Unicode cumulative risk score above block threshold | Provides score + primaryThreat metadata |

## Metrics Emitted (Selected)
| Metric | Trigger |
|--------|---------|
| `unicode.reject.combiningRatio` | Combining ratio over configured bound |
| `unicode.serialize.unsuccessful` | `_toString` JSON serialization failure |
| `unicode.structural.introduced` | Normalization introduced new structural delimiter(s) |
| `unicode.risk.metric.<id>` | Individual risk metric triggered (when scoring enabled) |

## Safe Bounds & Clamps
All numeric inputs undergo clamping / validation:
- `maxCombiningRatio` ∈ (0, 0.9]
- `normalizationIdempotencySampleRate` ≥ 1 integer
- `traversalTimeBudgetMs` clamped to ≤ 5000ms
- Depth & sizes validated as positive integers

These limits enforce a *no silent downgrade* policy—misconfiguration cannot raise risk surface beyond documented maxima.

## Migration Guidance
| Previous Behavior | New Secure Default | Action Needed |
|-------------------|--------------------|---------------|
| Silent cycle annotation | Throw on cycle | Set `circularPolicy: 'annotate'` to retain annotation |
| Unconditional idempotency check | Sampled idempotency | Set `normalizationIdempotencyMode: 'always'` for old behavior |
| Correlation hash in sanitized logs | Removed | None (if relied upon, switch to external hashing) |

## Examples
```ts
import { setUnicodeSecurityConfig, setCanonicalConfig } from '@david-osipov/security-kit';

setUnicodeSecurityConfig({
  maxCombiningRatio: 0.35,
  normalizationIdempotencyMode: 'sample',
  normalizationIdempotencySampleRate: 32,
});

setCanonicalConfig({
  circularPolicy: 'fail',
  traversalTimeBudgetMs: 40, // Slightly higher for large payloads
});
```

## Testing Strategy Alignment
- Mutation tests should flip comparison operators in combining ratio logic; rejection must still be caught.
- Fuzz tests can generate cycle-heavy proxy objects to ensure traversal budget enforces bounds.
- Adversarial Unicode test corpus should include near-threshold combining densities (just below and just above) to ensure precise boundary behavior.

## Future Extensions (Guardrails)
Any proposal to add new risk metrics MUST:
1. Justify threat classification.
2. Provide deterministic test vectors (benign vs malicious).
3. Avoid scope creep into non-Unicode WAF heuristics.

---
Security-first configuration is now explicit, bounded, and auditable. For further architectural rationale, consult `docs/Constitutions/Security Consitution.md`.
