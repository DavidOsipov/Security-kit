# Incremental / Streaming Unicode Normalizer Design (Draft)

Status: Draft (Phase 0 Exploration)
Target Module: `src/canonical-incremental.ts` (proposed)
Security Level: OWASP ASVS L3 – must not weaken existing guarantees
Author: Automated architectural assistant

## 1. Motivation
Current `normalizeInputString` requires the entire string in memory, performing:
1. Pre-validation (surrogates, bidi, invisibles, dangerous ranges)
2. NFKC normalization
3. Post-validation (structural introduction, combining limits)
4. Risk assessment (optional)

For extremely large but bounded inputs (e.g., streamed logs, chunked protocol frames, or controlled ingestion pipelines), holding the entire value in memory is undesirable. A streaming approach would:
- Reduce peak memory usage (process in fixed-size UTF-16 → code point windows)
- Allow early termination on policy violation (fail-fast)
- Provide progressive risk metrics (useful for adaptive throttling / telemetry)

## 2. Non-Goals
- Not a replacement for the existing canonical path (kept as the default safe API)
- No relaxation of validation rules or thresholds
- No multi-pass recomposition heuristics beyond standard NFKC semantics
- Not a cryptographic transform – integrity still handled separately

## 3. Threat Model & Security Requirements
| Concern | Mitigation |
|--------|-----------|
| Bidi Trojan Source | Detect and reject as soon as any bidi control appears |
| Invisible / Zero Width | Reject early during chunk scan |
| Surrogate pairing across chunk boundary | Maintain tail state to validate across boundaries |
| Combining sequence run limit | Track current run across chunk boundary; enforce MAX_COMBINING_CHARS_PER_BASE |
| Normalization expansion bomb | Maintain cumulative normalized length vs raw length ratio; abort if > MAX_NORMALIZED_LENGTH_RATIO |
| Structural introduction | Need original raw vs normalized comparison → buffer only risk chars presence bitset and introduced chars per chunk; finalize after full stream |
| Idempotency verification | Defer (optional) – streaming variant may provide weaker idempotency guarantee unless a final full-pass is performed (document explicit tradeoff) |
| PUA / variation selectors | Soft / hard policy same as core; enforce per code point |

## 4. Proposed API (Experimental)
```ts
interface StreamingNormalizationOptions {
  readonly maxBytes?: number;             // Hard cap (UTF-8 encoded length estimate)
  readonly emitIntermediate?: (state: StreamingNormalizationState) => void; // Optional observer
  readonly enableRiskScoring?: boolean;   // Same semantics as existing config (overrides global)
}

interface StreamingNormalizationState {
  readonly rawBytes: number;
  readonly normalizedLength: number;
  readonly expansionRatio: number;
  readonly combiningRun: number;
  readonly maxCombiningRun: number;
  readonly combiningRatioApprox: number; // approximate ratio using running counts
  readonly structuralIntroduced?: readonly string[]; // partial (observed so far)
  readonly aborted: boolean;
  readonly errorCode?: string;            // UnicodeErrorCode
}

class IncrementalNormalizer {
  constructor(options?: StreamingNormalizationOptions);
  write(chunk: string): void;             // Throws on violation
  finalize(): { value: string; risk?: UnicodeRiskAssessment };
  abort(reason?: string): void;           // Manual abort
}
```

## 5. Internal Architecture
- UTF-16 iteration per chunk using index-based scanning (avoid iterator allocations)
- Maintain rolling state:
  - `pendingHighSurrogate?: number` to handle boundary surrogate pairs
  - `currentCombiningRun`, `totalChars`, `totalCombining`
  - `rawStructuralSet` (Set of structural chars seen in raw input)
  - `introducedStructuralSet` (Set discovered after normalization – deferred evaluation per chunk: compare normalized vs raw slice)
- Per-chunk normalization: `chunk.normalize("NFKC")`
  - Risk: partial normalization can interact with boundaries (e.g., decomposition + recomposition across chunks). To mitigate, use a small overlap window:
    - Maintain `carry: string` of last `OVERLAP_GRAPHEME_MAX` code units (e.g., 8) and prepend to next chunk before normalization
    - After normalization, remove any prefix corresponding to previously emitted tail to avoid duplication
  - Document that extremely exotic sequences spanning > overlap window may degrade idempotency guarantee (practically negligible for security contexts)

## 6. Expansion Ratio Discipline
- Track `rawTotalLength` (UTF-16 code units) and `normalizedTotalLength`
- After each write: if `normalizedTotalLength > rawTotalLength * MAX_NORMALIZED_LENGTH_RATIO` → throw Expansion error

## 7. Structural Introduction Handling
Because we lack the entire pre-normalization string, we instead:
1. Track presence of structural risk chars encountered raw (`rawStructuralSet`)
2. After each normalized chunk: scan newly produced segment for structural chars; if any not in `rawStructuralSet`, stage them in `introducedStructuralSet`
3. On detection: immediately throw (same semantics as current logic) with sample indexes relative to cumulative normalized output length

## 8. Idempotency Consideration
Full idempotency check would require re-normalizing the entire normalized output – defeating streaming memory benefit.
- Option A (default): Skip secondary pass; annotate result with `idempotencyVerified: false`
- Option B (opt-in): If caller sets `options.enableIdempotencyCheck`, perform final pass (guarded by max size) at `finalize()`

## 9. Performance & Memory Targets
| Aspect | Target |
|--------|--------|
| Peak additional buffer | O(overlap window) ≤ 16 code units |
| Time complexity | O(n) single pass + optional O(n) final idempotency pass |
| Allocation pattern | Amortized append to array of segments, single join at finalize |

## 10. Error Mapping (All from errors.ts)
| Condition | Error Code |
|----------|------------|
| Bidi control | ERR_UNICODE_BIDI |
| Invisible | ERR_UNICODE_INVISIBLE |
| Variation selectors | ERR_UNICODE_VARIATION |
| Tag characters | ERR_UNICODE_TAG |
| Private Use Area | ERR_UNICODE_PUA |
| Dangerous range | ERR_UNICODE_DANGEROUS |
| Combining overrun | ERR_UNICODE_COMBINING |
| Expansion bomb | ERR_UNICODE_EXPANSION |
| Structural introduced | ERR_UNICODE_STRUCTURAL |
| Surrogate malformed | ERR_UNICODE_SURROGATE |

## 11. Security Analysis
- Streaming does not *expand* attack surface; identical rejection semantics preserved.
- Overlap window prevents incomplete canonical forms for typical decomposition sequences (e.g., Hangul, combining accents).
- Early abort reduces resource utilization for malicious payloads (improves DoS resilience – ASVS V1).
- Documentation must clearly mark experimental status and advise fallback to full normalization when absolute determinism (idempotency proof) required.

## 12. Testing Strategy
1. Unit tests: boundary surrogates across chunk edge, combining run spanning write boundary, structural introduction in second chunk.
2. Adversarial tests: simulate incremental feed of normalization bomb candidate – ensure early rejection.
3. Differential tests: compare full vs streaming output for randomized corpus under size threshold.
4. Mutation: remove overlap logic → should fail differential test.

## 13. Migration & API Stability
- Introduce behind feature flag `ENABLE_INCREMENTAL_NORMALIZER` (internal config) until hardened.
- No breaking changes to existing exports.

## 14. Open Questions
- Should we support async chunk sources (e.g., `for await (const chunk of stream)`) directly? (Future wrapper)
- Is overlap window tunable via config or fixed constant? (Start fixed; expose if needed)
- Integrate risk scoring incrementally (progressive scoring) vs final-only? (Phase 2)

## 15. Next Steps
1. Prototype `IncrementalNormalizer` (feature flagged, not exported in index).
2. Add differential test harness comparing against `normalizeInputString`.
3. Run mutation tests to ensure overlap removal is detected.
4. Evaluate memory usage vs baseline using synthetic large input (benchmarks/ addition).

---
**Decision:** Proceed with prototype behind feature flag; treat as experimental until differential + mutation coverage ≥ 95% equivalence across ≥ 10K randomized samples.
