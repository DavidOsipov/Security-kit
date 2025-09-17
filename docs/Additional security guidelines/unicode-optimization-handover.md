<!--
SPDX-License-Identifier: LGPL-3.0-or-later
-->
# Unicode Binary Optimization Handover (v2 Baseline)

## 1. Current State Summary
| Aspect | Status |
|--------|--------|
| Unicode Version | 16.0.0 |
| Identifier Ranges Format | v2 delta+varint (magic `U16R`, version 2) + legacy fallback (8-byte pairs) |
| Confusables Format | v2 split tables (magic `U16C`, version 2) + v1 legacy + pre-v1 fallback |
| Profiles | minimal (no mappings), standard (curated subset), complete (full sanitized set) |
| Raw Sizes (standard) | Ranges 845 B; Confusables 79,535 B |
| Gzip Sizes (standard) | Ranges 667 B; Confusables 38,388 B |
| Raw Sizes (complete) | Confusables 81,269 B (ranges identical) |
| Integrity Tests | Round-trip test validates identifiers + mapping fidelity |
| Instrumentation | `--stats` flag collects index usage, target reuse, prefix histogram (not persisted) |
| Security Caps | Mapping count ≤ 20,000; single/multi counts ≤ 20,000; multi bytes ≤ 1,000,000; range count ≤ 10,000 |

## 2. Achievements
- Identifier ranges compressed by ~73% raw, ~46% gzip vs legacy.
- Stable, versioned decoding with strict invariants & bounds checks.
- Backward compatibility retained (v1/pre-v1 confusables + legacy ranges for debugging).
- Deterministic, single-pass decoding (audit-friendly, low attack surface).
- Documentation updated (sections 1–8 in `unicode-binary-format.md`).

## 3. Outstanding Compression Opportunity (Confusables)
Current average bytes/mapping (raw) ~10.9; gzip ~5.27. Target (phase 2 goals):
- Raw ≤ 8.0 bytes/mapping.
- Gzip ≤ 4.5 bytes/mapping.

## 4. Key Data Dynamics (Inferred)
- High share of single→single mappings; flags add overhead but sometimes save 1 byte when both indices <256.
- Prefix overlap for multi sequences appears modest (instrumentation suggests need for per-bucket or alternative encoding for small sequences; exact histogram persistence TBD).
- Target reuse likely non-trivial (common canonical forms) — candidate for factoring.

## 5. Candidate Optimization Strategies (Prioritized)
| Priority | ID | Strategy | Rationale | Risk | Pre-Req |
|----------|----|----------|-----------|------|--------|
| 1 | O1 | Pure varint indices | Simplifies flags, shrinks many entries | Low | Add varint decode path tests |
| 2 | O2 | Frequency-based index remap | Better entropy clustering improves gzip | Low | Instrument usage stats (already) |
| 3 | O4 | Partition mapping tables | Removes 1 flag byte per entry | Med | Need new header counts + invariant tests |
| 4 | O3 | Target set factoring | Compress repeated targets | Med | Target reuse quantification |
| 5 | O5 | Multi delta encoding | Possibly smaller than prefix for short sequences | Med | Evaluate histogram first |
| 6 | O6 | Bucketed front-coding restarts | Reduces waste when overlap low | Low | Simple marker design |
| 7 | O7 | Optional checksum | Integrity improvement | Low | Add constant-time digest compare |
| 8 | O8 | Derived profiles at load | Shrink distribution duplication | Med/High | Guarantee deterministic filtering |

## 6. Security Guardrails (DO NOT BREAK)
1. All counts/lengths validated before allocations.
2. Varints limited to 5 bytes (ranges) / configurable smaller cap (indices) — fail fast on overflow.
3. Single-pass decode: no recursion, no dynamic code execution, no unbounded loops.
4. Reserved header bytes must remain zero (future version gating) — consider strict mode enforcement.
5. Fuzz test matrix (F1–F9) must be implemented before any new format revision release.
6. Backward compatibility: maintain existing v2 decoder branch; new structure requires version bump or additive header extension.
7. Timing: Avoid data-dependent early exits that reveal structural irregularities beyond coarse error classification (OK to throw typed error, not leak partial state).

## 7. Test Roadmap
| Phase | Additions |
|-------|-----------|
| A | Adversarial unit tests for F1–F9 (see format doc) |
| B | Mutation tests focusing on range monotonicity, index bounds, prefix validation |
| C | Differential test: regenerate with old script vs new index reassignment -> ensure semantic equivalence |
| D | Performance regression harness (measure decode ms & allocations) |
| E | Fuzz corpus seeds (malformed flags, clipped multi block, overlapping varints) |

## 8. Proposed v3 Header Changes (If Needed)
Potential extended confusables header (40 bytes): add fields after current 32 bytes:
| Offset | Size | Field | Purpose |
|--------|------|-------|---------|
| 32..35 | 4 | Mapping Block Bytes | Enable pre-validation & quick skip |
| 36..39 | 4 | Integrity Tag Length | If non-zero, integrity tag follows tables |
(Followed by optional integrity tag and mapping block.)

Ensure: keep magic/version stable; bump version to 3 if structure order changes.

## 9. Migration Strategy for Format Changes
1. Implement new encoder/decoder behind feature flag: `ENABLE_UNICODE_V3_EXPERIMENT=1`.
2. Generate dual binaries (v2 + experimental v3) during development; keep tests asserting semantic equivalence.
3. Add doc section & changelog entry; only promote once size & perf targets achieved and fuzz tests green.
4. Remove experimental generation path once stable and audited.

## 10. Tooling Enhancements (Future)
- Persist stats JSON artifact for CI diffing to catch regressions.
- Benchmark harness capturing decode time & heap usage across profiles (store historical baselines).
- Add CLI subcommand: `--emit-stats-json` to write structured metrics file.
- Add optional `--profile=<standard|complete>` override for targeted regen.

## 11. Acceptance Criteria for Declaring Optimization Phase Complete
| Dimension | Criterion |
|-----------|----------|
| Size | Raw ≤ 8.0 bytes/mapping (standard) & gzip ≤ 4.5 |
| Performance | Decode time regression <5% vs current v2 baseline |
| Safety | All adversarial + fuzz tests pass; no new high-severity issues |
| Integrity | Optional checksum (if added) verified in constant time |
| Docs | Updated spec + changelog + migration notes |

## 12. Immediate Next Actions (Recommended Order)
1. Implement adversarial tests F1–F9.
2. Prototype O1 (pure varint indices); measure delta; update instrumentation output.
3. If gain <5%, proceed with O2 (frequency remap) before O4.
4. Persist stats JSON for reproducibility.
5. Decide on integrity tag inclusion (checksum) post-size improvements.

## 13. Reference Files
| Path | Purpose |
|------|---------|
| `scripts/parse-unicode-data-optimized.ts` | Generator & instrumentation logic |
| `src/generated/unicode-optimized-loader.ts` | Runtime multi-version decoder |
| `docs/Additional security guidelines/unicode-binary-format.md` | Formal format spec & roadmap |
| `tests/unicode-audit/round-trip-integrity.test.ts` | Semantic integrity validation |
| (TODO) future adversarial tests | Structural & fuzz harness |

## 14. Risks & Mitigations
| Risk | Mitigation |
|------|-----------|
| Over-optimization causing decode complexity spike | Enforce single-pass rule; code review vs checklist |
| Hidden regression in mapping semantics | Differential tests vs v2 baseline |
| Fuzz gap introduces acceptance of malformed data | Expand corpus before release |
| Integrity tag timing leak | Use constant-time compare (byte-wise accumulator) |
| Non-deterministic index ordering (rebuild variance) | Stable sort and documented ordering rules |

## 15. Contact & Ownership
Primary maintainer: David Osipov
Security principles reference: Security Constitution (OWASP ASVS L3 alignment).

---
Handover complete. Proceed with Phase 2 optimizations respecting guardrails above.
