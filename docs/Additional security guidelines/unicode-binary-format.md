<!--
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# Unicode Binary Format - Technical Specification

**⚠️ MOVED**: The user-friendly documentation has moved to [`docs/User docs/unicode-data-format.md`](../User%20docs/unicode-data-format.md).

This document remains for technical specification details and internal development reference.

---

## 1. Identifier Ranges Format

File name pattern: `unicode-identifier-ranges-<profile>.bin`

Profiles: `minimal | standard | complete` (all share identical range file — only confusables differ).

### 1.1 Legacy (v1 / unversioned) Representation

```
repeat N times:
  uint32_le startCodePoint
  uint32_le endCodePoint
```

Total size = N * 8 bytes.

### 1.2 Version 2 Delta + Varint Representation (Magic `U16R`, Version = 2)

Header (12 bytes):

| Offset | Size | Field           | Notes                                        |
|--------|------|-----------------|----------------------------------------------|
| 0..3   | 4    | Magic           | ASCII `U16R`                                 |
| 4      | 1    | Version         | `2`                                          |
| 5..7   | 3    | Reserved        | MUST be zero                                 |
| 8..11  | 4    | Range Count     | uint32 LE                                    |

Payload encoding (after header):

```
varint firstRangeStart        // absolute start of first range
varint firstRangeLength       // (end - start + 1) of first range
repeat (rangeCount - 1) times:
  varint deltaStart           // (currentStart - previousStart)
  varint currentRangeLength   // (end - start + 1)
```

Varint: unsigned, base-128, little‑endian continuation (7 data bits per byte, high bit = continuation). Maximum 5 bytes (32‑bit safety cap). Any varint > 0x10FFFF for starts or producing end > 0x10FFFF is rejected.

Decoder reconstruction:
```
start_0 = firstRangeStart
end_0   = start_0 + firstRangeLength - 1
for each subsequent:
  start_i = start_{i-1} + deltaStart
  end_i   = start_i + currentRangeLength - 1
```

### 1.3 Semantics
All stored ranges are implicitly `Allowed`. Any code point not covered is `Restricted` per UTS #39. No status bytes are serialized.

### 1.4 Validation Invariants (Both Formats)
* For legacy: file length % 8 == 0
* For v2: header length ≥12, magic/version match, payload has exactly `rangeCount` ranges recoverable without overrun
* 0 <= start <= end <= 0x10FFFF
* Strictly ascending, non‑overlapping ranges (enforced by reconstruction ordering)
* No integer overflow in `start + length - 1`

### 1.5 Security / Performance Rationale
* Delta + varint drastically compresses clustered ranges (empirically ~73% reduction vs legacy for 16.0.0 data).
* Eliminating status byte avoids branchy decoding & shrinks memory footprint.
* Deterministic single-pass decode with constant extra space.
* Defensive parsing rejects malformed or suspiciously large varints early (≤5 bytes, else fail).

## 2. Confusables Format (Versioned)

File name pattern: `unicode-confusables-<profile>.bin`

Two on-disk schema versions are currently supported: v1 (string table + 16‑bit index pairs) and v2 (split single/multi tables with variable-length mapping entries and front‑coded multi sequences). The loader auto-detects by inspecting header size & version fields.

### 2.1 Version 1 (Magic `U16C`, Version = 1)

Header (16 bytes):

| Offset | Size | Field              | Notes                                        |
|--------|------|--------------------|----------------------------------------------|
| 0..3   | 4    | Magic              | ASCII `U16C`                                 |
| 4      | 1    | Version            | `1`                                          |
| 5      | 1    | Profile            | 0=minimal,1=standard,2=complete (advisory)   |
| 6..7   | 2    | Reserved           | MUST be zero                                 |
| 8..11  | 4    | String Table Size  | bytes (uint32 LE)                            |
| 12..15 | 4    | Mapping Count      | number of (src,tgt) pairs (uint32 LE)        |

Payload:
```
stringTable: NUL ('\0') separated UTF‑8 strings (trailing NUL)
mappings: mappingCount * 4 bytes of:
  uint16_le sourceIndex
  uint16_le targetIndex
```

### 2.2 Version 2 (Magic `U16C`, Version = 2)

Header (32 bytes):

| Offset | Size | Field                | Notes                                                                 |
|--------|------|----------------------|-----------------------------------------------------------------------|
| 0..3   | 4    | Magic                | ASCII `U16C`                                                          |
| 4      | 1    | Version              | `2`                                                                   |
| 5      | 1    | Profile              | 0=minimal,1=standard,2=complete                                       |
| 6..7   | 2    | Reserved             | MUST be zero                                                          |
| 8..11  | 4    | Single Count         | number of single codepoints                                           |
| 12..15 | 4    | Multi Count          | number of multi sequences                                             |
| 16..19 | 4    | Multi Bytes Size     | bytes occupied by front‑coded multi block                             |
| 20..23 | 4    | Mapping Count        | number of mapping entries                                             |
| 24..27 | 4    | Reserved (future)    | MUST be zero                                                          |
| 28..31 | 4    | Reserved (future)    | MUST be zero                                                          |

Immediately following the header:
```
singleTable: singleCount * 4 bytes (uint32_le code points)
multiTable:  multiBytesSize bytes (front‑coded sequences)
mappingTable: variable-length entries (mappingCount total)
```

Front‑coded multi table encoding:
```
repeat M times:
  uint8 prefixLen   // shared prefix length with previous decoded multi string
  uint8 suffixLen   // length of new suffix
  suffix bytes (UTF‑8) of length suffixLen
```
First entry MUST have prefixLen = 0. Reconstructed sequence = previousSequence[0:prefixLen] + suffix.

### 2.2.1 Mapping Entry Encoding (v2)
Each entry begins with a 1‑byte flag field:
```
bit 0 (0x01): source is multi (else single)
bit 1 (0x02): target is multi (else single)
bit 2 (0x04): source index small (1 byte) else 2 bytes little-endian
bit 3 (0x08): target index small (1 byte) else 2 bytes little-endian
bits 4..7    : MUST be zero (reserved)
```
Then the indices (order: sourceIndex, targetIndex) each encoded in 1 or 2 bytes as indicated. Single indices address `singleTable`. Multi indices address the logical multi sequence list recovered from front‑coding (0‑based). Bounds checks enforced:
* source single index < singleCount
* source multi index < multiCount
* target indices analogous

### 2.2.2 Safety Caps (Parser & Loader)
* `MAX_MAPPING_COUNT = 20,000`
* `MAX_SINGLE_COUNT = 20,000`
* `MAX_MULTI_COUNT  = 20,000`
* `MAX_MULTI_BYTES  = 1,000,000`
* All mapping entries must fit exactly; no trailing data permitted

### 2.2.3 Rationale
* Splitting single vs multi eliminates redundant storage of short strings & leverages fixed 4‑byte code point representation for O(1) indexing.
* Front‑coding exploits high prefix sharing in multi sequences (scripts with combining marks / repeated starting letters).
* Small index flag path collapses many entries to 3 bytes total (flags + 2 single‑byte indices) vs 4 bytes in v1.
* Reserved header space allows future integrity tags (CRC32 / BLAKE3) or extended counts without reflowing layout.

### 2.3 Backward Compatibility & Detection
Loader logic:
* If first 4 bytes `U16C` and header length available ≥32 and version==2 -> decode v2.
* Else if `U16C` and version==1 -> decode v1.
* Else fallback to legacy unversioned (pre‑v1) if length heuristic matches (string table + pairs) — still supported for transitional audit only.

### 2.4 Common Validation for Both Versions
* Profile byte ∈ {0,1,2}
* All indices in bounds
* No zero-length multi sequences
* UTF‑8 decode must succeed (constructed internally, so logic asserts length consistency)
* Mapping count must not exceed cap

### 2.5 Data Minimization & Filtering
Same semantic filters as v1 (see Section 2.1). Standard profile retains curated high‑risk subset; minimal profile intentionally ships zero mappings (size = tiny header only) to guarantee fast load path in strict environments.

Dropped at parse time (applies to all versions):
* Unicode descriptions (e.g., `LATIN LETTER RETROFLEX CLICK`)
* Comment redirection chains (only final mapping retained)
* Self‑identity mappings
* Control-only / bidi-only sequences
* Pure case-only ASCII single-character confusables (mitigated elsewhere)

Backward compatibility guarantees (confusables): Existing consumers using public API remain unaffected; internal loader chooses correct path. Future major changes MUST either (a) introduce new magic or (b) bump version and extend reserved fields while preserving prior decode branch.

## 3. Threat Model & Hardening

| Threat                       | Mitigation |
|------------------------------|------------|
| Malicious expansion attack   | Hard caps (ranges, mappingCount, table sizes); immediate rejection. |
| Binary truncation / partial  | Structural length checks (exact consumption); varint overrun detection. |
| Index corruption             | Every index bounds-checked; multi prefix lengths validated. |
| Varint abuse / overflow      | Max 5‑byte varints; reject >32‑bit or >0x10FFFF range starts. |
| Overlapping / invalid ranges | Reconstructed sequentially; any non‑monotonic delta aborts. |
| Prototype pollution via data | Only primitive arrays/strings returned; no object merging. |
| Timing inference             | Pure data decode; no secret-dependent branching. |
| Memory pressure DoS          | Allocation sized after validated counts & caps. |
| Front-coding corruption      | PrefixLen must ≤ previous length; suffixLen >0 unless first entry. |

Potential future enhancement: add CRC32 (or BLAKE3 truncated) integrity tag after header for tamper detection. Omitted initially to keep binary minimal; indices/structure checks already catch most corruption cases.

## 4. OWASP ASVS Mapping (Selected)

| ASVS Control (abridged)           | Implementation |
|-----------------------------------|----------------|
| V5: Validation of Inputs          | Hex parsing strict regex; discard malformed lines & comments. |
| V5: Size & Resource Limits        | Mapping & table caps; explicit early throws. |
| V5: Malformed Data Handling       | Fail-fast on structural inconsistencies (length, indices). |
| V6: Output Encoding/Sanitization  | Only internally constructed UTF-8; no external injection. |
| V8: Integrity / Trust Boundaries  | Magic + versioning; planned checksum extension. |
| V14: Configuration Hardening      | Profiles isolated; minimal ships no confusables. |

## 5. Usage Contract
Consumer APIs (`getIdentifierRanges`, `getConfusables`, etc.) must treat absence of a mapping as "no confusable risk" rather than error. New binary versions MUST remain backward compatible or be guarded by a major version bump of the library.

## 6. Test & Audit Guarantees
* Format unit test validates magic, version, and profile bytes.
* Audit tool reconstructs sample ranges & mappings, checking structural integrity.
* CI should add fuzz tests (future) that mutate header bytes, shorten payload, and scramble indices to ensure robust failure modes.

## 7. Change Log (Format)
* v2 (current): Added delta+varint identifier ranges (magic `U16R`), split confusables schema (single vs multi, front‑coding, variable-length mapping entries, reserved header space). Backward compatible with v1 & legacy.
* v1: Introduced versioned confusables header (magic `U16C`, profile byte, caps). Legacy unversioned string table + pairs still accepted.

## 8. Instrumentation & Optimization Roadmap

### 8.1 Build-Time Instrumentation (`--stats` Flag)
The generator (`scripts/parse-unicode-data-optimized.ts`) accepts a `--stats` flag. When present it enriches the in-memory confusables binary object with a stats side-channel and (optionally) emits structured summaries.

Collected Metrics (per profile):
* `singleIndexUsage` – Top single-code-point indices by total participation (source+target). Includes source frequency `s`, target frequency `t`, aggregate `Σ`, and original index.
* `multiIndexUsage` – Same statistics for multi sequences (front-coded payload entries).
* `targetReuseTop` – Most frequently reused target sequences (helps evaluate benefit of target set factoring).
* `prefixOverlapHistogram` – Distribution of front-coding prefix lengths (buckets 0..14, 15+). Low prefix reuse indicates diminishing returns of global front-coding and informs alternate packing strategies.

Current Empirical Outcomes (Unicode 16.0.0):
* Identifier ranges: 3,128 bytes (legacy) → 845 bytes (v2 delta+varint) raw (−72.99%); gzip 1,240 → 667 bytes (−46.2%).
* Confusables: Structural v2 redesign (header + split tables + flags) did not yet reduce aggregate raw size; additional strategies below target further gains.

### 8.2 Candidate Optimization Strategies
| ID | Strategy | Expected Gain* | Complexity | Key Security Constraints |
|----|----------|----------------|-----------|--------------------------|
| O1 | Replace small/large flag with pure varint indices | 0.2–0.4 B/mapping | Low | Cap varint length (≤3 bytes); bounds checks each decode |
| O2 | Frequency-based index reassignment | 5–10% gzip | Low/Med | Deterministic ordering; reproducible build documentation |
| O3 | Target set factoring (source→targetSetIdx) | 5–15% raw (if reuse high) | Med | Cap set count; validate membership & indices |
| O4 | Partition mapping tables by cardinality (S→S, S→M, M→S, M→M) | Remove 1 flag byte / entry | Med | Four counts + monotonic decode path |
| O5 | Multi sequence delta (code point varints instead of UTF-8 + prefix) | TBD | Med | Code point range & total length caps |
| O6 | Per-bucket / group front-coding restarts | Modest | Low | Validate restart markers; no unbounded state |
| O7 | Optional integrity checksum (CRC32/BLAKE3-16) | +Integrity (size +24–32B) | Low | Constant-time compare; no partial acceptance |
| O8 | Ship complete only + derive standard/minimal at load | Distribution shrink | Med/High | Derivation O(n) with caps; profile purity guaranteed |

*Estimates are directional; validate with instrumentation after prototype.

### 8.3 Planned Adversarial / Fuzz Cases
| Case | Description | Required Behavior |
|------|-------------|-------------------|
| F1 | Truncated v2 header (<32 bytes) | Reject: structural error |
| F2 | Varint >5 bytes | Reject: varint too long |
| F3 | Mapping count implies overflow beyond file length | Reject: truncated mappings |
| F4 | PrefixLen > previous sequence length | Reject: corrupt multi table |
| F5 | Small-index flag but index ≥256 | Reject: index out of bounds |
| F6 | Delta ranges non-monotonic (negative delta) | Reject: invalid ordering |
| F7 | MultiBytesSize overflow (extends past file end) | Reject: bounds error |
| F8 | Reserved header bytes non-zero (strict mode) | Warn or reject (configurable) |
| F9 | Extremely large counts within caps but causing memory pressure | Early allocation check & reject |

### 8.4 Design Guardrails
* Single-pass deterministic decode (no multi-phase dictionary rebuilds).
* Hard numerical caps precede allocations; fail before large memory commitments.
* Every future table adds: explicit count field, cap, and bounds check loop.
* Any optional integrity mechanism must not leak timing differences between valid and invalid inputs beyond constant factors (use constant-time comparison for digest verification if added).

### 8.5 Success Criteria for Confusables Compression Phase 2
* Raw bytes per mapping ≤ 8.0 (currently ~10.9 standard profile).
* Gzip bytes per mapping ≤ 4.5 (currently ~5.27).
* Decoder CPU time not degraded >5% vs current v2 on representative workloads.
* All adversarial tests (F1–F9) pass; mutation tests show no surviving mutants in boundary checks.

### 8.6 Usage Examples
Generate (lean):
```
node scripts/parse-unicode-data-optimized.ts
```
Generate with stats:
```
node scripts/parse-unicode-data-optimized.ts --stats
```

### 8.7 Future Metrics Persistence (Not Yet Implemented)
Potential JSON artifact: `src/generated/unicode-stats-<profile>.json` capturing metrics above plus: mapping flag pattern frequency, average bytes/mapping, entropy estimates. Persist only in development builds to avoid shipping analysis data.

### 8.8 Roadmap Snapshot
1. Add adversarial decoder tests (F1–F9).
2. Prototype O1 (pure varint indices) & measure.
3. If gain <5%, pivot to O2 (frequency remap) before heavier transformations.
4. Evaluate target reuse; if reuse hotspot >4 sources per target median, prototype O3.
5. Reassess against success criteria; introduce checksum only after structural stability.

For enhancement proposals (checksum, compression codec differentiation, multi‑version bundling), open an issue referencing this document section.
