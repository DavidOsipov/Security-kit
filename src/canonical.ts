// SPDX-License-Identifier: LGPL-3.0-or-later
// SPDX-FileCopyrightText: © 2025 David Osipov <personal@david-osipov.vision>
/**
 * Security Kit Canonicalization & Unicode Normalization (Option A Scope)
 * ---------------------------------------------------------------------
 * This module deliberately focuses ONLY on:
 *   - Safe Unicode NFKC normalization
 *   - Detection/rejection of: Bidi controls, invisibles, dangerous ranges,
 *     excessive combining marks, normalization expansion anomalies, and
 *     structural delimiter introduction post-normalization.
 *   - Deterministic canonical object/value serialization utilities.
 *
 * Removed (previous experimental WAF responsibilities):
 *   - Generic XSS / <script> pattern blocking
 *   - SQLi / shell / path traversal regex heuristics
 *   - Multi-pass percent / URL decoding & unified scoring engine
 *   - Public unsafe bypass helper (normalizeInputStringInternal)
 *
 * Rationale (Security Constitution Pillars):
 *   Pillar #1 (Verifiable Security): Narrow scope => easier to reason about & test.
 *   Pillar #2 (Hardened Simplicity): Eliminates brittle heuristic filters.
 *   Pillar #3 (Ergonomic API): Single safe normalization path; no insecure variants.
 *   Pillar #4 (Provable Correctness): Enables high-confidence adversarial & mutation tests
 *   without exploding combinatorial surface of unrelated attack classes.
 *
 * Consumers MUST layer dedicated defenses for context-specific threats:
 *   - HTML / DOM sanitization: use the Sanitizer utilities (src/sanitizer.ts)
 *   - SQL injection: use parameterized queries at the data layer
 *   - Shell command safety: avoid shell concat; use spawn with argv arrays
 *   - Path traversal: validate normalized filesystem paths separately
 *
 * Any feature request to re-expand this file should first justify why it
 * cannot live in a dedicated, testable module with clear threat boundaries.
 */
import {
  InvalidParameterError,
  CircuitBreakerError,
  makeInvalidParameterError,
  makeDepthBudgetExceededError,
  SecurityValidationError,
  CanonicalizationDepthError,
  CanonicalizationTraversalError,
} from "./errors.ts";
import { SHARED_ENCODER } from "./encoding.ts";
import { isForbiddenKey } from "./constants.ts";
import {
  secureCompareAsync,
  secureDevLog as secureDevelopmentLog,
  emitMetric,
} from "./utils.ts";
import {
  getCanonicalConfig,
  getUnicodeSecurityConfig,
  MAX_CANONICAL_INPUT_LENGTH_BYTES,
  MAX_NORMALIZED_LENGTH_RATIO,
  MAX_COMBINING_CHARS_PER_BASE,
  BIDI_CONTROL_CHARS,
  INVISIBLE_CHARS,
  HOMOGLYPH_SUSPECTS,
  DANGEROUS_UNICODE_RANGES,
  STRUCTURAL_RISK_CHARS,
  SHELL_INJECTION_CHARS,
} from "./config.ts";
// Public Unicode data exports are re-exported later; we don't need to import them here.
// (Removed unused placeholder import for UnicodeDataStats to keep file lint-clean.)

// ================= Option A Core Helpers (restored after refactor) =================

// Sentinel to mark nodes currently under processing in the cache (used by canonicalization)
const PROCESSING = Symbol("__processing");

// ================= Unicode Risk Assessment (OWASP ASVS L3) =================
// Centralized Unicode / structural cumulative risk scoring for normalization.
// Immutable, side-effect-free assessment to satisfy functional & security lint rules.
// All scoring signals are soft (hard fails still enforced earlier in canonical path).

export type UnicodeRiskMetric = {
  readonly id: string;
  readonly weight: number; // assigned if triggered
  readonly triggered: boolean;
  readonly detail?: unknown;
};

export type UnicodeRiskAssessment = {
  readonly total: number;
  readonly primaryThreat: string;
  readonly metrics: readonly UnicodeRiskMetric[];
  /** Schema version for the Unicode risk assessment shape (future‑proofing & auditability). */
  readonly schemaVersion: typeof UNICODE_RISK_ASSESSMENT_SCHEMA_VERSION;
};

// Centralized spec for Unicode risk metrics (Pillar #1 transparency). Tests can
// assert stability; changing weights requires updating rationale comment.
export const UNICODE_RISK_METRICS_SPEC: ReadonlyArray<{
  readonly id: string;
  readonly weight: number;
  readonly rationale: string;
}> = Object.freeze([
  {
    id: "bidi",
    weight: 40,
    rationale: "Bidirectional control characters enable Trojan Source / visual reordering attacks.",
  },
  {
    id: "invisibles",
    weight: 20,
    rationale: "Invisible/zero-width chars hide content or delimiters; medium severity vs bidi.",
  },
  {
    id: "expansionSoft",
    weight: 15,
    rationale: "Moderate normalization expansion may indicate mild obfuscation without surpassing hard fail ratio.",
  },
  {
    id: "combiningDensity",
    weight: 20,
    rationale: "High combining mark density strains rendering & can conceal characters.",
  },
  {
    id: "combiningRun",
    weight: 15,
    rationale: "Localized spike of combining marks may indicate targeted spoofing.",
  },
  {
    id: "mixedScriptHomoglyph",
    weight: 25,
    rationale: "Mixed scripts with known homoglyph suspects raise phishing/impersonation risk.",
  },
  {
    id: "lowEntropy",
    weight: 15,
    rationale: "Low-entropy dominated strings often part of obfuscation padding or flooding.",
  },
  {
    id: "introducedStructural",
    weight: 35,
    rationale: "Structural delimiter introduced only after normalization can alter parsing semantics.",
  },
] as const);

// Helper to test combining marks category M (Mn/Mc/Me) cheaply.
const COMBINING_RE = /^\p{M}$/u;

// === Precompiled regexes & immutable sets (ASVS V5.3.4 safe regex usage) ===
const RE_BIDI_GLOBAL = new RegExp(BIDI_CONTROL_CHARS, "gu");
const RE_INVISIBLE_GLOBAL = new RegExp(INVISIBLE_CHARS, "gu");
const RE_SHELL_GLOBAL = new RegExp(SHELL_INJECTION_CHARS, "gu");

// Static structural risk character list (explicit, auditable; no runtime derivation)
const STRUCTURAL_RISK_CHAR_LIST: readonly string[] = Object.freeze([
  "/",
  "\\",
  ":",
  "@",
  "#",
  "?",
  "&",
  "=",
  "%",
  "<",
  ">",
  '"',
  "'",
  "`",
  "$",
  "|",
  ";",
  "(",
  ")",
  "{",
  "}",
  "[",
  "]",
  "~",
  "*",
  "!",
]);
const STRUCTURAL_RISK_CHARS_SET: ReadonlySet<string> = new Set(
  STRUCTURAL_RISK_CHAR_LIST,
);
export const __test_structuralRiskChars = STRUCTURAL_RISK_CHAR_LIST;

// (Removed legacy correlation hash constants – hashing replaced by marker run-length encoding.)

function computeCombiningRatio(s: string): {
  readonly ratio: number;
  readonly maxRun: number;
} {
  let combining = 0;
  let currentRun = 0;
  let maxRun = 0;
  for (const ch of s) {
    if (COMBINING_RE.test(ch)) {
      combining++;
      currentRun++;
      if (currentRun > maxRun) maxRun = currentRun;
    } else {
      currentRun = 0;
    }
  }
  const ratio = s.length === 0 ? 0 : combining / s.length;
  return Object.freeze({ ratio, maxRun });
}

function computeLowEntropy(s: string): boolean {
  // Heuristic intentionally lightweight (non-cryptographic). Two triggers:
  // 1. Single character dominates >50% of length (original heuristic).
  // 2. Cumulative top <=4 characters account for >=80% of length.
  // Only applied for reasonably large inputs (>=40) to avoid noise.
  if (s.length < 40) return false;
  const counts = new Map<string, number>();
  let maxSingle = 0;
  // Early termination: once remaining length cannot reduce top coverage
  // below threshold, we can decide outcome.
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    const next = (counts.get(ch) ?? 0) + 1;
    counts.set(ch, next);
    if (next > maxSingle) maxSingle = next;
    if (maxSingle / s.length > 0.5) return true; // condition 1 satisfied
    if (counts.size > 256) break; // cardinality cap (DoS bound)
  }
  // Condition 2: compute coverage of top four characters. This is O(k log k)
  // for k<=256 => negligible. Avoid full map sort by partial selection.
  const topCounts = Array.from(counts.values())
    .sort((a, b) => b - a)
    .slice(0, 4);
  const coverage = topCounts.reduce((a, b) => a + b, 0) / s.length;
  return coverage >= 0.8;
}

function detectIntroducedStructuralInternal(
  raw: string,
  normalized: string,
): boolean {
  if (raw === normalized) return false;
  if (!STRUCTURAL_RISK_CHARS.test(normalized)) return false;
  // Build raw presence set (bounded to risk chars only)
  const rawSet = new Set<string>();
  for (const ch of raw) {
    if (STRUCTURAL_RISK_CHARS.test(ch)) rawSet.add(ch);
  }
  for (const ch of normalized) {
    if (STRUCTURAL_RISK_CHARS.test(ch) && !rawSet.has(ch)) return true;
  }
  return false;
}

const UNICODE_RISK_ASSESSMENT_SCHEMA_VERSION = 1 as const;

function assessUnicodeRisks(raw: string, normalized: string): UnicodeRiskAssessment {
  const unicodeCfg = getUnicodeSecurityConfig();
  // ASCII fast-path should not call this; assume at least one non-ASCII or previously validated unicode.
  const expansionRatio = raw.length === 0 ? 1 : normalized.length / raw.length;
  const combining = computeCombiningRatio(normalized);
  const mixedScript =
    /[A-Za-z]/u.test(normalized) &&
    /\p{Letter}/u.test(normalized.replace(/[A-Za-z]/gu, "")) &&
    HOMOGLYPH_SUSPECTS.test(normalized);
  const lowEntropy = computeLowEntropy(normalized);
  const introducedStructural = detectIntroducedStructuralInternal(
    raw,
    normalized,
  );

  const metrics: readonly UnicodeRiskMetric[] = Object.freeze(
    UNICODE_RISK_METRICS_SPEC.map((spec): UnicodeRiskMetric => {
      const overrideWeight = unicodeCfg.riskMetricWeights?.[spec.id];
      const weight = typeof overrideWeight === "number" ? overrideWeight : spec.weight;
      switch (spec.id) {
        case "bidi":
          return {
            id: spec.id,
            weight,
            triggered:
              BIDI_CONTROL_CHARS.test(raw) ||
              BIDI_CONTROL_CHARS.test(normalized),
          } as UnicodeRiskMetric;
        case "invisibles":
          return {
            id: spec.id,
            weight,
            triggered:
              INVISIBLE_CHARS.test(raw) || INVISIBLE_CHARS.test(normalized),
          } as UnicodeRiskMetric;
        case "expansionSoft":
          return {
            id: spec.id,
            weight,
            triggered:
              expansionRatio > 1.2 &&
              expansionRatio <= MAX_NORMALIZED_LENGTH_RATIO,
            detail: expansionRatio,
          } as UnicodeRiskMetric;
        case "combiningDensity":
          return {
            id: spec.id,
            weight,
            triggered: combining.ratio > 0.2 && combining.ratio <= 0.3,
            detail: combining.ratio,
          } as UnicodeRiskMetric;
        case "combiningRun":
          return {
            id: spec.id,
            weight,
            triggered: combining.maxRun > 3 && combining.maxRun <= 5,
            detail: combining.maxRun,
          } as UnicodeRiskMetric;
        case "mixedScriptHomoglyph":
          return {
            id: spec.id,
            weight,
            triggered: mixedScript,
          } as UnicodeRiskMetric;
        case "lowEntropy":
          return {
            id: spec.id,
            weight,
            triggered: lowEntropy,
          } as UnicodeRiskMetric;
        case "introducedStructural":
          return {
            id: spec.id,
            weight,
            triggered: introducedStructural,
          } as UnicodeRiskMetric;
        default:
          return {
            id: spec.id,
            weight,
            triggered: false,
          } as UnicodeRiskMetric;
      }
    }),
  );

  let total = 0;
  let primaryThreat = "none";
  let topWeight = -1;
  for (const m of metrics) {
    if (m.triggered) {
      total += m.weight;
      if (m.weight > topWeight) {
        topWeight = m.weight;
        primaryThreat = m.id;
      }
    }
  }
  return Object.freeze({
    total,
    primaryThreat,
    metrics,
    schemaVersion: UNICODE_RISK_ASSESSMENT_SCHEMA_VERSION,
  });
}

// (Removed broader WAF/unified risk scoring. File now focuses strictly on
// Unicode normalization & structural canonicalization.)

/**
 * Convert unknown input to a string safely without triggering hostile toString() methods.
 * Minimal version retained for Unicode normalization entrypoints.
 */
function _toString(input: unknown): string {
  if (typeof input === "string") return input;
  if (typeof input === "number")
    return Number.isFinite(input) ? String(input) : "";
  if (typeof input === "boolean") return String(input);
  if (typeof input === "bigint") return input.toString();
  if (input === null || input === undefined) return "";
  try {
    const json = JSON.stringify(input);
    return typeof json === "string" ? json : "";
  } catch (error) {
    try { emitMetric("unicode.serialize.unsuccessful", 1, {}); } catch { /* noop */ }
    secureDevelopmentLog(
      "warn",
      "_toString",
      "JSON serialization failed during safe coercion",
      { error: error instanceof Error ? error.message : String(error) },
    );
    return "[UNSERIALIZABLE]";
  }
}
// ================= Unicode Security Validation (Option A focused) =================
// Core Unicode threat detection: BIDI controls, invisibles, dangerous ranges,
// excessive combining marks, and basic homoglyph suspicion logging. This is a
// deliberately *narrow* scope versus prior unified WAF logic.

function validateUnicodeSecurity(string_: string, context: string): void {
  if (string_.length === 0) return;
  const config = getUnicodeSecurityConfig();
  if (string_.length > config.maxInputLength) {
    throw new InvalidParameterError(
      `${context}: Input exceeds Unicode validation max length (${String(config.maxInputLength)}).`,
    );
  }

  // We intentionally sequence checks in order of (a) security criticality and (b) expected rarity.
  // This minimizes total regex passes for common benign inputs (performance hardening, Pillar #2).
  // Bidirectional control characters (Trojan Source class)
  if (config.rejectBidiControls && BIDI_CONTROL_CHARS.test(string_)) {
    const seen = new Set<string>();
    RE_BIDI_GLOBAL.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = RE_BIDI_GLOBAL.exec(string_)) !== null) {
      seen.add(match[0]);
      if (seen.size >= 10) break; // cap collection for message size
    }
    const matches = Array.from(seen);
    const msg = config.detailedErrorMessages
      ? `${context}: Contains bidirectional control characters (${matches.join(",")}) — rejected to prevent Trojan Source attacks.`
      : `${context}: Contains bidirectional control characters.`;
    try { emitMetric("unicode.reject.bidi", matches.length, { context }); } catch { /* noop */ }
    throw new InvalidParameterError(msg);
  }

  // Invisible / zero-width characters (excluding standard whitespace) – deny.
  // Only executed if Bidi test did not already throw, avoiding double work on hostile inputs containing both.
  if (config.rejectInvisibleChars && INVISIBLE_CHARS.test(string_)) {
    const invSet = new Set<string>();
    RE_INVISIBLE_GLOBAL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = RE_INVISIBLE_GLOBAL.exec(string_)) !== null) {
      invSet.add(m[0]);
      if (invSet.size >= 5) break;
    }
    const inv = Array.from(invSet);
    const msg = config.detailedErrorMessages
      ? `${context}: Contains invisible/zero-width characters (${inv.join(",")}).`
      : `${context}: Contains invisible/zero-width characters.`;
    try { emitMetric("unicode.reject.invisible", inv.length, { context }); } catch { /* noop */ }
    throw new InvalidParameterError(msg);
  }

  // Dangerous control / non-character ranges
  if (config.rejectDangerousRanges && DANGEROUS_UNICODE_RANGES.test(string_)) {
    try { emitMetric("unicode.reject.dangerousRange", 1, { context }); } catch { /* noop */ }
    throw new InvalidParameterError(
      `${context}: Contains disallowed control/unassigned characters.`,
    );
  }

  // Excessive combining marks / normalization bombs
  _validateCombiningCharacterLimits(string_, context);

  // Raw shell character blocking (optional, off by default)
  if (config.blockRawShellChars && SHELL_INJECTION_CHARS.test(string_)) {
    const shellSet = new Set<string>();
    RE_SHELL_GLOBAL.lastIndex = 0;
    let shellMatch: RegExpExecArray | null;
    while ((shellMatch = RE_SHELL_GLOBAL.exec(string_)) !== null) {
      shellSet.add(shellMatch[0]);
      if (shellSet.size >= 10) break; // cap collection for message size
    }
    const shellChars = Array.from(shellSet);
    throw new InvalidParameterError(
      `${context}: Contains shell metacharacters (${shellChars.join(",")}) — raw shell injection guard enabled.`,
    );
  }

  // Lightweight homoglyph suspicion logging (non-fatal) if mixed script risk
  // Present: ASCII letter + suspicious homoglyph pattern + non-ASCII letter.
  if (config.enableConfusablesDetection && /[A-Za-z]/u.test(string_)) {
    // Detect presence of any non-ASCII letter alongside ASCII letters when
    // homoglyph suspects regex also matches; avoids complex character class
    // intersections not supported in all engines.
    if (
      HOMOGLYPH_SUSPECTS.test(string_) &&
      /\p{Letter}/u.test(string_.replace(/[a-z]/giu, ""))
    ) {
      secureDevelopmentLog(
        "warn",
        "validateUnicodeSecurity",
        "Potential mixed-script homoglyph risk detected",
        { context, length: string_.length },
      );
    }
  }
}

/**
 * Calculate homoglyph and Unicode validation scores
 * @internal
 */
// Removed calculateHomoglyphScores and related scoring aggregation per Option A.

/**
 * Calculate contextual scoring modifiers based on input characteristics
 * @internal
 */

/**
 * Detect excessive combining characters (DoS protection for OWASP ASVS L3).
 * Prevents denial-of-service attacks where many combining marks are applied
 * to a single base character, which can cause expensive normalization and
 * rendering operations.
 *
 * Example attack: "a" + "\u0301".repeat(1000) creates 1000 combining acute accents
 * on a single 'a', causing performance degradation in processing and display.
 *
 * @param string_ - String to validate for excessive combining characters
 * @param context - Context for error reporting
 * @throws InvalidParameterError when excessive combining characters are detected
 */
function _validateCombiningCharacterLimits(
  string_: string,
  context: string,
): void {
  const unicodeCfg = getUnicodeSecurityConfig();
  let baseCharCount = 0; // mutable counters: single linear scan for performance
  let combiningCharCount = 0;
  let consecutiveCombining = 0;

  for (const char of string_) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined) continue; // skip malformed surrogate edge (defensive)

    // Check if character is a combining mark (General Category Mn, Mc, Me)
    // Unicode ranges for combining marks:
    // - Combining Diacritical Marks (0300-036F)
    // - Combining Diacritical Marks Extended (1AB0-1AFF)
    // - Combining Diacritical Marks Supplement (1DC0-1DFF)
    // - Combining Half Marks (FE20-FE2F)
    const isCombining =
      (codePoint >= 0x0300 && codePoint <= 0x036f) ||
      (codePoint >= 0x1ab0 && codePoint <= 0x1aff) ||
      (codePoint >= 0x1dc0 && codePoint <= 0x1dff) ||
      (codePoint >= 0xfe20 && codePoint <= 0xfe2f) ||
      // Check Unicode general category for combining marks
      /^\p{M}/u.test(char);

    if (isCombining) {
      combiningCharCount += 1;
      consecutiveCombining += 1;

      // Check for excessive combining characters on single base character
      if (consecutiveCombining > MAX_COMBINING_CHARS_PER_BASE) {
        throw new InvalidParameterError(
          `${context}: Excessive combining characters detected (${consecutiveCombining} consecutive). ` +
            `Maximum ${MAX_COMBINING_CHARS_PER_BASE} combining marks per base character allowed.`,
        );
      }
    } else {
      baseCharCount += 1;
      consecutiveCombining = 0; // Reset counter for new base character
    }
  }

  // Additional check: if more than 30% of characters are combining marks in larger inputs, likely an attack
  // Only apply this check for strings with substantial content (>20 chars) to avoid false positives
  const totalChars = baseCharCount + combiningCharCount;
  const ratio = totalChars === 0 ? 0 : combiningCharCount / totalChars;
  if (
    totalChars > unicodeCfg.minCombiningRatioScanLength &&
    ratio > unicodeCfg.maxCombiningRatio
  ) {
    try { emitMetric("unicode.reject.combiningRatio", ratio, { context }); } catch { /* noop */ }
    throw new InvalidParameterError(
      `${context}: Suspicious ratio of combining characters (${String(combiningCharCount)}/${String(totalChars)} = ${(ratio * 100).toFixed(2)}%). Possible combining character DoS attack (limit ${(unicodeCfg.maxCombiningRatio * 100).toFixed(1)}%).`,
    );
  }
}

/**
 * Detect structural metacharacters introduced only after normalization.
 * If a character in STRUCTURAL_RISK_CHARS appears in the normalized output
 * but not in the raw input, treat as potential host/split or delimiter
 * smuggling and reject (OWASP ASVS L3: prevent canonicalization bypass).
 *
 * This mitigates attacks where visually benign Unicode variants normalize
 * into structural separators that alter downstream parsing semantics
 * (URL host boundaries, path traversal, query injection).
 *
 * @param raw - Original untrusted string (pre-normalization)
 * @param normalized - NFKC-normalized result
 * @param context - Context for error reporting
 * @throws InvalidParameterError when new structural characters are introduced
 */
function detectIntroducedStructuralChars(
  raw: string,
  normalized: string,
  context: string,
): void {
  if (raw === normalized) return;

  // Fast exit: if normalized contains none of the risk chars, skip further work.
  if (!STRUCTURAL_RISK_CHARS.test(normalized)) return;

  // Micro‑optimization (Phase 1): replace repeated RegExp.test per character with
  // Set membership to lower per‑char overhead in hot paths. We intentionally
  // duplicate the character list from the central regex to avoid parsing the
  // pattern at runtime – if the central definition changes, this list MUST be
  // updated in tandem (kept small & auditable).
  // Use shared immutable STRUCTURAL_RISK_CHARS_SET (defined above).

  // Build set of structural chars present in the raw (pre‑normalization) input.
  const inRaw = new Set<string>();
  for (const ch of raw) {
    if (STRUCTURAL_RISK_CHARS_SET.has(ch)) inRaw.add(ch);
  }

  const introduced = new Array<string>();
  for (const ch of normalized) {
    if (STRUCTURAL_RISK_CHARS_SET.has(ch) && !inRaw.has(ch))
      introduced.push(ch);
  }
  if (introduced.length === 0) return;

  const unique = Array.from(new Set(introduced));
  secureDevelopmentLog(
    "warn",
    "detectIntroducedStructuralChars",
    "Normalization introduced structural delimiter(s)",
    { context, introduced: unique },
  );
  try {
    emitMetric("unicode.structural.introduced", unique.length, {
      context,
      chars: unique.join(""),
    });
  } catch {
    /* metric emission failures are non-fatal */
  }
  const unicodeCfg = getUnicodeSecurityConfig();
  if (!unicodeCfg.rejectIntroducedStructuralChars) {
    // Soft path: emit a warning & metric but do not fail closed when config disabled (non-production only).
    try { emitMetric("unicode.structural.introduced.soft", unique.length, { context }); } catch { /* noop */ }
    return;
  }
  const msg = unicodeCfg.detailedErrorMessages
    ? `${context}: Normalization introduced structural characters (${unique.join(", ")}).`
    : `${context}: Normalization introduced structural characters.`;
  try { emitMetric("unicode.reject.introducedStructural", unique.length, { context }); } catch { /* noop */ }
  throw new InvalidParameterError(msg);
}

// Verifies NFKC normalization idempotency; if a second pass changes the string, treat as anomaly.
// Lightweight fingerprint cache for idempotency checks. We intentionally keep
// this extremely small (32 entries) to bound memory and avoid timing side‑channels.
// Key = length + first + last + xor accumulator of code points.
// Value = original normalized string reference (to detect if environment changed behavior).
const IDEMPOTENCY_CACHE_MAX = 32;
// eslint-disable-next-line functional/no-let -- bounded mutable cache for performance
let _idempotencyCache: Map<string, string> | undefined;

function fingerprintForIdempotency(s: string): string {
  // XOR + length + boundary chars. Provides cheap heuristic uniqueness.
  let xor = 0;
  // Limit work for very long strings by sampling every 8th code point after 1024.
  const len = s.length;
  const sampleStride = len > 1024 ? 8 : 1;
  for (let i = 0; i < len; i += sampleStride) {
    xor ^= s.charCodeAt(i) & 0xffff;
  }
  const first = s.charCodeAt(0) & 0xffff;
  const last = s.charCodeAt(len - 1) & 0xffff;
  return `${len}:${first}:${last}:${xor}`;
}

function maybeVerifyNormalizationIdempotent(normalized: string, context: string): void {
  const cfg = getUnicodeSecurityConfig();
  const mode = cfg.normalizationIdempotencyMode;
  if (mode === 'off') return;
  if (/^[\x20-\x7E]*$/u.test(normalized)) return; // ASCII stable

  // Heuristic skip via fingerprint cache (only for 'sample' or 'always').
  const fp = fingerprintForIdempotency(normalized);
  if (_idempotencyCache?.get(fp) === normalized) {
    // Previously verified unchanged; skip second normalization entirely.
    if (mode === 'sample') {
      // Still respect sampling randomness; we could early return regardless,
      // but keeping the sampling gate ensures periodic re-validation.
      const rate = Math.max(1, cfg.normalizationIdempotencySampleRate);
      const first = normalized.charCodeAt(0) || 0;
      if (((normalized.length ^ first) % rate) !== 0) return;
    } else {
      return; // mode === 'always' but cached -> trust until eviction
    }
  } else if (mode === 'sample') {
    const rate = Math.max(1, cfg.normalizationIdempotencySampleRate);
    const first = normalized.charCodeAt(0) || 0;
    if (((normalized.length ^ first) % rate) !== 0) return;
  }

  try {
    const second = normalized.normalize('NFKC');
    if (second !== normalized) {
      secureDevelopmentLog(
        'warn',
        'maybeVerifyNormalizationIdempotent',
        'Normalization was not idempotent on verification pass',
        { context, firstLength: normalized.length, secondLength: second.length },
      );
      throw new InvalidParameterError(`${context}: Normalization not idempotent (environment anomaly).`);
    }
    // Update cache (create lazily to avoid cost when mode='off').
    if (!_idempotencyCache) _idempotencyCache = new Map();
    if (!_idempotencyCache.has(fp)) {
      if (_idempotencyCache.size >= IDEMPOTENCY_CACHE_MAX) {
        // Evict oldest insertion (Map preserves insertion order)
        const firstKey = _idempotencyCache.keys().next().value as string | undefined;
        if (firstKey !== undefined) _idempotencyCache.delete(firstKey);
      }
    }
    _idempotencyCache.set(fp, normalized);
  } catch (error) {
    if (error instanceof InvalidParameterError) throw error;
    throw new InvalidParameterError(`${context}: Failed idempotency verification.`);
  }
}

/**
 * Normalize string input using NFKC to prevent Unicode normalization attacks.
 * Enhanced for OWASP ASVS Level 3 compliance with comprehensive security hardening:
 * - DoS protection via input length limits (2KB default, configurable via options.maxLength)
 * - Trojan Source attack detection (Boucher & Anderson, 2021)
 * - Bidirectional control character detection
 * - Invisible/zero-width character detection
 * - Homoglyph attack prevention
 * - Normalization bomb prevention (2x expansion ratio limit)
 * - Combining character DoS prevention (max 5 per base character)
 * - Dangerous Unicode range validation
 *
 * SECURITY NOTE: The default 2KB limit balances security and usability.
 * Most legitimate inputs (URLs, identifiers, form fields) are much smaller.
 * Larger limits increase DoS attack surface via memory/CPU exhaustion.
 * Override only when absolutely necessary via options.maxLength.
 *
 * Protects against:
 * - Visual spoofing attacks via bidirectional overrides
 * - Content hiding via invisible characters
 * - Character spoofing via homoglyphs
 * - Supply chain attacks via Trojan Source patterns
 *
 * NFKC (Normalization Form Compatibility Composition) provides the strictest
 * normalization, collapsing visually similar characters into common equivalents.
 *
 * OWASP ASVS v5 V5.1.4: Unicode normalization for input validation
 * Security Constitution: Fail Loudly - normalize to detect bypass attempts
 *
 * @param input - The input value to normalize (converted to string first)
 * @param context - Optional context for error reporting (defaults to "input")
 * @returns The NFKC-normalized string
 * @throws InvalidParameterError for security violations or DoS attempts
 */
export function normalizeInputString(
  input: unknown,
  context = "input",
  options?: { readonly maxLength?: number },
): string {
  const rawString = _toString(input);

  // Phase 1 performance improvement (Pillar #2: Hardened Simplicity & Performance):
  // Fast‑path for common ASCII‑only inputs (printable + space). This avoids
  // running the full Unicode validation & normalization pipeline when it would
  // be a no‑op. Security is preserved because ASCII printable characters are
  // already in stable NFKC form and cannot introduce structural characters via
  // normalization. Length checks still apply below for DoS protection.
  // NOTE: We deliberately exclude control characters (<0x20 except space) to
  // force them through full validation (they would be rejected later anyway).
  if (rawString.length > 0 && /^[\x20-\x7E]*$/u.test(rawString)) {
    // Still enforce byte length limit before returning early.
    const lengthLimit =
      typeof options?.maxLength === "number" && options.maxLength > 0
        ? Math.min(options.maxLength, MAX_CANONICAL_INPUT_LENGTH_BYTES)
        : MAX_CANONICAL_INPUT_LENGTH_BYTES;
    const rawBytesFast = SHARED_ENCODER.encode(rawString);
    if (rawBytesFast.length > lengthLimit) {
      throw new InvalidParameterError(
        `${context}: Input exceeds maximum allowed size (${lengthLimit} bytes).`,
      );
    }
    return rawString;
  }

  // DoS protection: check raw input length before processing
  const lengthLimit =
    typeof options?.maxLength === "number" && options.maxLength > 0
      ? Math.min(options.maxLength, MAX_CANONICAL_INPUT_LENGTH_BYTES)
      : MAX_CANONICAL_INPUT_LENGTH_BYTES;

  const rawBytes = SHARED_ENCODER.encode(rawString);
  if (rawBytes.length > lengthLimit) {
    throw new InvalidParameterError(
      `${context}: Input exceeds maximum allowed size (${lengthLimit} bytes).`,
    );
  }

  // Apply Unicode security validation before normalization
  if (rawString.length > 0) {
    validateUnicodeSecurity(rawString, context);
  }

  // Perform NFKC normalization with error handling
  let normalized: string;
  try {
    normalized = rawString.normalize("NFKC");
  } catch (e) {
    secureDevelopmentLog(
      "error",
      "normalizeInputString",
      "Normalization threw exception",
      { context, error: e instanceof Error ? e.message : String(e) },
    );
    throw new InvalidParameterError(
      `${context}: Failed to normalize input securely.`,
    );
  }

  // Prevent normalization bombs - check expansion ratio
  if (normalized.length > rawString.length * MAX_NORMALIZED_LENGTH_RATIO) {
    throw new InvalidParameterError(
      `${context}: Normalization resulted in excessive expansion, potential normalization bomb.`,
    );
  }

  // NEW: Detect structural delimiter introduction (host/split style attacks)
  detectIntroducedStructuralChars(rawString, normalized, context);

  // NEW: Verify normalization idempotency (defense-in-depth)
  maybeVerifyNormalizationIdempotent(normalized, context);

  // Re-validate after normalization to catch newly introduced dangerous patterns
  if (normalized.length > 0) {
    validateUnicodeSecurity(normalized, context);
  }

  // Passive cumulative risk scoring (defense-in-depth, optional)
  const unicodeCfg = getUnicodeSecurityConfig();
  if (unicodeCfg.enableRiskScoring) {
    const assessment = assessUnicodeRisks(rawString, normalized);
    if (assessment.total >= unicodeCfg.riskBlockThreshold) {
      throw new SecurityValidationError(
        "Unicode cumulative risk threshold exceeded",
        assessment.total,
        unicodeCfg.riskBlockThreshold,
        assessment.primaryThreat,
        "Reject or further sanitize input before use in security-sensitive context.",
        context,
      );
    }
    if (assessment.total >= unicodeCfg.riskWarnThreshold) {
      secureDevelopmentLog(
        "warn",
        "normalizeInputString",
        "Unicode cumulative risk warning",
        {
          context,
          score: assessment.total,
          primaryThreat: assessment.primaryThreat,
        },
      );
    }
    if (unicodeCfg.onRiskAssessment) {
      try {
        const frozenMetrics = Object.freeze(
          assessment.metrics.map((m) =>
            Object.freeze({
              id: m.id,
              score: m.weight,
              triggered: m.triggered,
            })
          ),
        );
        const payload = Object.freeze({
          score: assessment.total,
          schemaVersion: UNICODE_RISK_ASSESSMENT_SCHEMA_VERSION,
          metrics: frozenMetrics,
          primaryThreat: assessment.primaryThreat,
          context,
        });
        unicodeCfg.onRiskAssessment(payload);
        // Emit telemetry after successful callback to avoid duplicate events if callback throws.
        try {
          emitMetric("unicode.risk.total", assessment.total, {
            context,
            primary: assessment.primaryThreat,
          });
          for (const m of assessment.metrics) {
            if (m.triggered) {
              emitMetric(`unicode.risk.metric.${m.id}`, m.weight, { context });
            }
          }
        } catch {
          /* ignore metric emission errors */
        }
      } catch (error) {
        secureDevelopmentLog(
          "warn",
          "normalizeInputString",
          "Risk assessment hook threw",
          { error: error instanceof Error ? error.message : String(error) },
        );
      }
    }
  }

  return normalized;
}

/**
 * Internal normalization function for trusted URL components and library operations.
 * Performs only NFKC normalization without security validation.
 *
 * IMPORTANT: This function MUST NOT be used for external/untrusted input.
 * Use normalizeInputString() for all external input validation.
 *
 * This function exists to prevent the architectural issue where URL building
 * functions were applying security validation to literal URL component characters
 * like ".", ":", "//" which is inappropriate and causes legitimate operations to fail.
 *
 * @param input - The trusted input to normalize (converted to string first)
 * @param context - Optional context for error reporting (defaults to "internal")
 * @returns The NFKC-normalized string without security validation
 * @throws InvalidParameterError only for normalization failures, not security violations
 */
// INTERNAL (no export): simplified internal helper retained only for localized
// performance-sensitive use within this module if ever needed. Public callers
// must always use normalizeInputString for full validation.
// NOTE: Previous versions exposed an unsafe bypass helper (normalizeInputStringInternal)
// that skipped security validation. Per architectural refactor (Option A), this
// has been removed to eliminate misuse risk and maintain a single, consistent
// normalization + validation pipeline. All internal callers must use
// normalizeInputString with appropriate context labels.

/**
 * Normalize and validate URL components with context-specific security rules.
 * @param input - The URL component to normalize
 * @param componentType - Type of URL component for context-specific validation
 * @returns The normalized and validated URL component
 */

/**
 * Timing-safe string comparison using normalized input.
 * Combines Unicode normalization with constant-time comparison to prevent
 * both normalization attacks and timing attacks.
 *
 * @param a - First string to compare
 * @param b - Second string to compare
 * @param context - Optional context for error reporting
 * @returns Promise resolving to true if strings are equal after normalization
 */
export async function normalizeAndCompareAsync(
  a: unknown,
  b: unknown,
  context = "comparison",
): Promise<boolean> {
  try {
    const normalizedA = normalizeInputString(a, context);
    const normalizedB = normalizeInputString(b, context);
    return await secureCompareAsync(normalizedA, normalizedB);
  } catch (error) {
    secureDevelopmentLog(
      "warn",
      "normalizeAndCompareAsync",
      `Normalization failed during comparison: ${error instanceof Error ? error.message : String(error)}`,
      { context },
    );
    return false;
  }
}

/**
 * Validate and normalize input for safe logging.
 * Removes or replaces potentially dangerous Unicode sequences while preserving
 * readability for debugging purposes.
 *
 * @param input - The input to sanitize for logging
 * @param maxLength - Maximum length for truncation (default: 200)
 * @returns Sanitized string safe for logging
 */
export function sanitizeForLogging(
  input: unknown,
  maxLength = 200,
  _options?: { readonly includeRawHash?: boolean },
): string {
  try {
    // Defensive lower bound: extremely tiny maxLength values can produce
    // confusing partial markers (e.g., cutting "[CTRL]"). Enforce a
    // practical minimum of 16 so truncation tokens remain intelligible.
    if (maxLength < 16) maxLength = 16; // eslint-disable-line no-param-reassign -- Intentional normalization of caller parameter (safe, primitive number)
    let string_ = _toString(input);
    // Hard cap raw length prior to normalization to bound normalization & hashing cost
    // independent of caller-provided maxLength (defense-in-depth). 8192 chosen as
    // generous diagnostic window while preventing log amplification / CPU spikes.
    const HARD_LOG_SANITIZE_CAP = 8192; // characters
    if (string_.length > HARD_LOG_SANITIZE_CAP) {
      string_ = string_.slice(0, HARD_LOG_SANITIZE_CAP);
    }

    // Apply basic normalization but catch any security violations
    // and replace dangerous content rather than throwing
    let sanitized: string;
    try {
      sanitized = string_.normalize("NFKC");
    } catch (error) {
      // SECURITY: Normalization failure should not expose the original string
      // Log the error for debugging but provide a safe fallback
      secureDevelopmentLog(
        "warn",
        "sanitizeForLogging",
        "NFKC normalization failed during sanitization",
        { error: error instanceof Error ? error.message : String(error) },
      );
      sanitized = string_; // Use original string as fallback
    }

    // Replace dangerous Unicode ranges with safe placeholders
    // Replace control characters safely for logging without triggering lint rules
    let cleanedString = sanitized
      .replace(BIDI_CONTROL_CHARS, "[BIDI]")
      .replace(DANGEROUS_UNICODE_RANGES, "[CTRL]");

    // Manual replacement of dangerous control characters
    const controlCharCodes = [
      1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
      24, 25, 26, 27, 28, 29, 30, 31, 127,
    ];
    for (const code of controlCharCodes) {
      const char = String.fromCharCode(code);
      cleanedString = cleanedString.replaceAll(char, "[CTRL]");
    }

  cleanedString = collapseControlMarkerRuns(cleanedString);
  cleanedString = capMarkerRepetitions(cleanedString);
  sanitized = cleanedString;

    // Truncate if too long using deterministic token. We reserve space for
    // the truncation marker to avoid ambiguous tail fragments.
    const TRUNC_TOKEN = "…[truncated]"; // single Unicode ellipsis + explicit marker
    if (sanitized.length > maxLength) {
      const sliceEnd = Math.max(0, maxLength - TRUNC_TOKEN.length);
      sanitized = sanitized.slice(0, sliceEnd) + TRUNC_TOKEN;
    }

    // Hard post-condition: ensure final string (excluding optional hash)
    // never exceeds maxLength + small hash suffix window. This guards against
    // any future modifications that might expand markers unexpectedly.
    if (sanitized.length > maxLength + 4) {
      sanitized = sanitized.slice(0, maxLength) + TRUNC_TOKEN; // enforce strict cap
    }

    // Include raw hash in output if requested
    return sanitized;
  } catch (error) {
    // SECURITY: If all sanitization fails, return a safe placeholder
    secureDevelopmentLog(
      "error",
      "sanitizeForLogging",
      "Complete sanitization failure",
      { error: error instanceof Error ? error.message : String(error) },
    );
    return "[INVALID_INPUT]";
  }
}

/**
 * Compute correlation hash for logging deduplication.
 *
 * Uses a simple but adequate hash since logging must be synchronous.
 * For cryptographic integrity, use crypto.subtle.digest("SHA-256", ...) asynchronously.
 */
// correlation hash removed – replaced with marker run-length encoding

/**
 * Cap repetitions of logging markers to prevent log flooding attacks.
 */
function capMarkerRepetitions(input: string, maxRepetitions = 5): string {
  const markers = ["[BIDI]", "[CTRL]", "[INVALID]"];
  let result = input;

  for (const marker of markers) {
    const escapedMarker = marker.replace(/[[\]]/g, "\\$&");
    const regex = new RegExp(`(${escapedMarker})\\1{${maxRepetitions},}`, "g");
    const replacement = `${marker.repeat(maxRepetitions)}[+${maxRepetitions}more]`;
    result = result.replace(regex, replacement);
  }

  return result;
}

function collapseControlMarkerRuns(input: string): string {
  // Collapse any run of combined control markers ([CTRL] or [BIDI]) of length >=4
  // into a single aggregate token preserving total count. Mixed sequences like
  // [CTRL][BIDI][CTRL][BIDI]...[CTRL] are aggregated into [CTRL|BIDI]xN to
  // prevent log amplification via alternating distinct markers.
  const pattern = /(?:(?:\[CTRL\])|(?:\[BIDI\])){4,}/g;
  return input.replace(pattern, (segment) => {
    const ctrlCount = (segment.match(/\[CTRL\]/g) || []).length;
    const bidiCount = (segment.match(/\[BIDI\]/g) || []).length;
    const total = ctrlCount + bidiCount;
    if (bidiCount === 0) return `[CTRL]x${total}`;
    if (ctrlCount === 0) return `[BIDI]x${total}`;
    return `[CTRL|BIDI]x${total}`;
  });
}

/**
 * Comprehensive input validation for external data.
 * Performs multiple layers of security checks before normalization.
 *
 * @param input - The input to validate
 * @param options - Validation options
 * @returns Validation result with normalized value or error details
 */
export function validateAndNormalizeInput(
  input: unknown,
  options: {
    readonly context?: string;
    readonly maxLength?: number;
    readonly allowEmpty?: boolean;
    readonly requireAscii?: boolean;
  } = {},
):
  | { readonly success: true; readonly value: string }
  | { readonly success: false; readonly error: string } {
  const {
    context = "input",
    maxLength = MAX_CANONICAL_INPUT_LENGTH_BYTES,
    allowEmpty = true,
    requireAscii = false,
  } = options;

  try {
    const rawString = _toString(input);

    // Early validation checks
    if (!allowEmpty && rawString.length === 0) {
      return Object.freeze({
        success: false,
        error: `${context}: Empty input not allowed.`,
      });
    }

    // Check for ASCII-only requirement using safe character range
    if (requireAscii && !/^[\x20-\x7E\t\n\r]*$/u.test(rawString)) {
      return Object.freeze({
        success: false,
        error: `${context}: Non-ASCII characters not allowed.`,
      });
    }

    // Check size before normalization
    const rawBytes = SHARED_ENCODER.encode(rawString);
    if (rawBytes.length > maxLength) {
      return Object.freeze({
        success: false,
        error: `${context}: Input exceeds maximum size (${maxLength} bytes).`,
      });
    }

    // Perform normalization with full validation
    const normalized = normalizeInputString(rawString, context);

    return Object.freeze({ success: true, value: normalized });
  } catch (error) {
    // Log for development debugging
    secureDevelopmentLog(
      "error",
      "validateAndNormalizeInput",
      "String normalization failed",
      { error: error instanceof Error ? error.message : String(error) },
    );
    return Object.freeze({
      success: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/**
 * Ultra-strict string validation for high-security contexts.
 * Applies the most restrictive Trojan Source protections with ASCII-only enforcement.
 * Use this for critical security boundaries like authentication tokens, API keys, etc.
 *
 * @param input - The input to validate with maximum security
 * @param context - Context for error reporting
 * @param options - Validation options
 * @returns Validated ASCII-only string
 * @throws InvalidParameterError for any security violations
 */
export function normalizeInputStringUltraStrict(
  input: unknown,
  context: string,
  options: {
    readonly maxLength?: number;
    readonly allowedChars?: RegExp;
  } = {},
): string {
  const { maxLength = 512, allowedChars = /^[\w.-]+$/u } = options;

  const rawString = _toString(input);

  if (rawString.length === 0) {
    throw new InvalidParameterError(
      `${context}: Empty input not allowed in ultra-strict mode.`,
    );
  }

  if (rawString.length > maxLength) {
    throw new InvalidParameterError(
      `${context}: Input exceeds ultra-strict maximum length (${maxLength}).`,
    );
  }

  // Immediate rejection of any non-ASCII characters using safe printable range
  if (!/^[\x20-\x7E\t\n\r]*$/u.test(rawString)) {
    const nonAsciiChars = Array.from(rawString)
      .filter((char) => char.charCodeAt(0) > 127)
      .map(
        (char) =>
          `'${char}' (U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")})`,
      )
      .slice(0, 5) // Limit to first 5 for readability
      .join(", ");

    secureDevelopmentLog(
      "error",
      "normalizeInputStringUltraStrict",
      `Non-ASCII characters rejected in ultra-strict mode`,
      { context, nonAsciiChars, inputLength: rawString.length },
    );

    throw new InvalidParameterError(
      `${context}: Non-ASCII characters not allowed in ultra-strict mode: ${nonAsciiChars}`,
    );
  }

  // Apply standard normalization (should be no-op for ASCII)
  const normalized = rawString.normalize("NFKC");

  // Verify allowed character set
  if (!allowedChars.test(normalized)) {
    throw new InvalidParameterError(
      `${context}: Contains characters not allowed in ultra-strict mode.`,
    );
  }

  // Final security validation (should pass for ASCII-only content)
  validateUnicodeSecurity(normalized, context);

  return normalized;
}

/**
 * Specialized function for validating URL-safe strings with Trojan Source protections.
 * Ideal for URL components, query parameters, and similar web contexts.
 *
 * @param input - The input to validate for URL safety
 * @param context - Context for error reporting
 * @param options - Validation options
 * @returns URL-safe normalized string
 * @throws InvalidParameterError for any security violations
 */

/**
 * Narrow/TypeGuard: returns true only for non-null objects.
 * Using an explicit helper eliminates ambiguous truthy checks that trigger
 * strict-boolean-expression lint errors and documents intent (ASVS: clear
 * input validation and explicit type discrimination).
 */
function isNonNullObject(
  value: unknown,
): value is Record<PropertyKey, unknown> {
  return value !== null && value !== undefined && typeof value === "object";
}

/**
 * Safe property assignment used during canonicalization. Centralizing this
 * logic lets us validate keys once and avoid repeated justifications for the
 * security/detect-object-injection rule. We explicitly reject forbidden keys
 * (prototype pollution vectors) and silently ignore anything non-string. The
 * target objects passed here are created with a null prototype so even if a
 * dangerous key slipped through (it cannot due to isForbiddenKey), it would
 * not mutate Object.prototype. (OWASP ASVS L3: object property injection /
 * prototype pollution hardening.)
 */
function safeAssign(
  target: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  if (typeof key !== "string") return; // defensive: only string keys
  if (isForbiddenKey(key)) return; // drop known dangerous keys
  // Reflect.set used instead of direct assignment to avoid accidental getters
  // invocation differences in the future and to make intent explicit.
  Reflect.set(target, key, value);
}

/**
 * Handles canonicalization of primitive values.
 */
function canonicalizePrimitive(value: unknown): unknown {
  if (value === undefined) return undefined;
  // eslint-disable-next-line unicorn/no-null
  if (value === null) return null; // preserve null distinctly from undefined

  const t = typeof value;
  if (t === "string" || t === "boolean") return value;

  if (t === "number") {
    return Number.isFinite(value as number) ? value : undefined;
  }

  if (t === "bigint") {
    // Nested BigInt must be rejected per security policy. Throw a specific
    // InvalidParameterError so callers can handle this deterministically.
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }

  if (t === "symbol" || t === "function") return undefined;

  return value; // fallback for other types
}

/**
 * Handles canonicalization of arrays with cycle/duplicate tracking.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Array canonicalization needs explicit index-based traversal, cache checks, and guarded conversions to meet security/perf constraints
function canonicalizeArray(
  value: readonly unknown[],
  cache: WeakMap<object, unknown>,
  depthRemaining: number | undefined,
  deadline: number,
  circularPolicy: 'fail' | 'annotate',
): unknown {
  if (Date.now() > deadline) {
    throw new CanonicalizationTraversalError('Canonicalization time budget exceeded.');
  }
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new CanonicalizationDepthError('Canonicalization depth budget exceeded.');
  }
  const asObject = value as unknown as object;
  const existing = cache.get(asObject);
  if (existing === PROCESSING) {
    if (circularPolicy === 'fail') throw new CanonicalizationTraversalError('Circular reference detected (policy=fail).');
    return { __circular: true };
  }
  if (existing !== undefined) return existing;

  cache.set(asObject, PROCESSING);

  // Build result explicitly from numeric indices to avoid inheriting
  // enumerable properties from Array.prototype (prototype pollution).
  // Preserve standard Array prototype so callers relying on array methods
  // (e.g., .filter/.map in safeStableStringify) continue to work.
  const length = (value as { readonly length?: number }).length ?? 0;
  // Create an array with null prototype to avoid inherited pollution
  // Use a mutable array type for construction; we still create with null prototype
  // to avoid inherited pollution.
  // Use a mutable array instance with a null prototype. We only perform
  // index-based writes; no Array.prototype methods are relied upon.
  // Use a mutable array type locally for index assignments; prototype is null to avoid pollution.
  // eslint-disable-next-line functional/prefer-readonly-type -- We use a local mutable array as a builder; result is not exposed externally
  const result: unknown[] = new Array<unknown>(length >>> 0);
  // eslint-disable-next-line functional/immutable-data, unicorn/no-null -- Setting a null prototype is an intentional, one-time hardening step against prototype pollution per Security Constitution
  Object.setPrototypeOf(result, null as unknown as object);
  // eslint-disable-next-line functional/no-let -- Index-based loop avoids iterator surprises and is faster/safer under hostile prototypes
  for (let index = 0; index < result.length; index++) {
    // eslint-disable-next-line functional/no-let -- Assigned in try/catch; using const would complicate control flow
    let element: unknown;
    try {
      // If the index does not exist on the source array, treat as undefined
      // (will later be serialized as null by stringify).
      // Access inside try/catch to guard against exotic hosts throwing.
      element = Object.hasOwn(value, index)
        ? (value as unknown as Record<number, unknown>)[index]
        : undefined;
      // eslint-disable-next-line local/no-broad-exception-swallow -- Controlled fallback: exotic object property access may throw; undefined assignment is safe fallback for array canonicalization
    } catch {
      element = undefined;
    }

    if (isNonNullObject(element)) {
      const ex = cache.get(element);
      if (ex === PROCESSING) {
        // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- Index is a loop-controlled number; not attacker-controlled; assigning into array with null prototype is safe.
        result[index] = { __circular: true };
        continue;
      }
      if (ex !== undefined) {
        // Duplicate reference to an already-processed node — reuse existing canonical form
        // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- See rationale above; controlled numeric index write.
        result[index] = ex;
        continue;
      }
    }
    // Enforce explicit rejection of BigInt values located inside arrays
    if (typeof element === "bigint") {
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }
    // eslint-disable-next-line functional/immutable-data, security/detect-object-injection -- Controlled numeric index write; key space not influenced by attacker beyond array length already bounded earlier.
    result[index] = toCanonicalValueInternal(
      element,
      cache,
      depthRemaining === undefined ? undefined : depthRemaining - 1,
      deadline,
      circularPolicy,
    );
  }
  const frozen = Object.freeze(result);
  cache.set(asObject, frozen);
  return frozen;
}

/**
 * Detects arrays produced by the canonicalizer (null prototype & frozen).
 * This helps downstream code decide whether it can safely rely on the array
 * having no prototype methods (e.g., avoid calling .map directly) and instead
 * treat it as a plain indexable sequence. Provided as a convenience utility
 * to reduce repeated instanceof / prototype checks by consumers.
 */
export function isCanonicalArray(value: unknown): value is readonly unknown[] {
  if (!Array.isArray(value)) return false;
  try {
    // Null prototype & frozen are the two invariants enforced by canonicalizeArray.
    if (Object.getPrototypeOf(value) !== null) return false;
    return Object.isFrozen(value);
  } catch {
    return false;
  }
}
/**
 * Handles canonicalization of objects with proxy-friendly property discovery.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Complex object canonicalization with multiple exotic object types and proxy handling
function canonicalizeObject(
  value: Record<string, unknown>,
  cache: WeakMap<object, unknown>,
  depthRemaining: number | undefined,
  deadline: number,
  circularPolicy: 'fail' | 'annotate',
): unknown {
  if (Date.now() > deadline) {
    throw new CanonicalizationTraversalError('Canonicalization time budget exceeded.');
  }
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new CanonicalizationDepthError('Canonicalization depth budget exceeded.');
  }
  const existing = cache.get(value as object);
  if (existing === PROCESSING) {
    if (circularPolicy === 'fail') throw new CanonicalizationTraversalError('Circular reference detected (policy=fail).');
    return { __circular: true };
  }
  if (existing !== undefined) return existing;

  cache.set(value as object, PROCESSING);

  // ArrayBuffer at object position → {}
  try {
    if (value instanceof ArrayBuffer) {
      const empty = {} as Record<string, unknown>;

      cache.set(value as object, empty);
      return empty;
    }
  } catch (error) {
    // SECURITY: ArrayBuffer access could fail with exotic objects
    // Continue canonicalization with fallback handling
    secureDevelopmentLog(
      "warn",
      "canonicalizeObject",
      "ArrayBuffer instanceof check failed",
      { error: error instanceof Error ? error.message : String(error) },
    );
  }

  // RegExp → {}
  if (value instanceof RegExp) {
    const empty = {} as Record<string, unknown>;

    cache.set(value as object, empty);
    return empty;
  }

  // Other exotic objects → {}
  const tag = Object.prototype.toString.call(value);
  const exoticTags = new Set([
    "[object Promise]",
    "[object WeakMap]",
    "[object WeakSet]",
    "[object Map]",
    "[object Set]",
    "[object URL]",
    "[object URLSearchParams]",
    "[object Error]",
  ]);
  if (exoticTags.has(tag)) {
    const empty = {} as Record<string, unknown>;
    cache.set(value as object, empty);
    return empty;
  }

  // Discover keys via ownKeys (strings only). We do not add Object.keys twice;
  // enumerability is validated when reading descriptors below. We defer adding
  // proxy probe keys until we detect accessor presence or descriptor failures
  // to reduce surface for DoS via expensive proxy traps (Pillar #2 hardening).
  const keySet = new Set<string>();
  for (const k of Reflect.ownKeys(value)) {
    if (typeof k === "string") keySet.add(k);
  }
  let addedProxyProbeKeys = false;
  const maybeAddProxyProbeKeys = (): void => {
    if (addedProxyProbeKeys) return;
    addedProxyProbeKeys = true;
    const alpha = "abcdefghijklmnopqrstuvwxyz";
    for (let index = 0; index < alpha.length; index++) {
      keySet.add(alpha.charAt(index));
      keySet.add(alpha.charAt(index).toUpperCase());
    }
  };

  const keys = Array.from(keySet).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  // Create the result with a null prototype up-front so we never perform
  // assignments onto a default Object.prototype bearing object. This reduces
  // the surface for prototype pollution and allows safeAssign to remain a
  // thin wrapper (ASVS L3: Use of secure object construction patterns).
  const result: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  // Descriptor attempt cap prevents unbounded cost on hostile proxies with
  // expensive getters or throwing property traps.
  let descriptorAttempts = 0;
  const MAX_DESCRIPTOR_ATTEMPTS = 512; // Tunable; small to bound worst-case cost.

  for (const k of keys) {
    // Skip forbidden keys (e.g., __proto__, prototype, constructor) to avoid
    // exposing or reintroducing prototype pollution via canonicalized output.
    // Per sanitizer policy, we silently drop these keys instead of throwing.
    if (isForbiddenKey(k)) {
      continue;
    }

    // Prefer data descriptors that are enumerable; fall back to direct access
    // eslint-disable-next-line functional/no-let -- Intentional let for descriptor handling in canonicalization
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptorAttempts++;
      if (descriptorAttempts > MAX_DESCRIPTOR_ATTEMPTS) {
        throw new CircuitBreakerError("Descriptor attempt cap exceeded");
      }
      descriptor = Object.getOwnPropertyDescriptor(value, k) ?? undefined;
    } catch (error) {
      // On descriptor failure we treat as proxy-like and add probe keys once.
      maybeAddProxyProbeKeys();
      descriptor = undefined;
      if (error instanceof CircuitBreakerError) throw error;
    }

    // eslint-disable-next-line functional/no-let -- Intentional let for raw value handling in canonicalization
    let raw: unknown;
    if (descriptor !== undefined) {
      if (descriptor.enumerable === true && "value" in descriptor) {
        raw = descriptor.value;
      } else if ("get" in descriptor || "set" in descriptor) {
        // Accessor detected: treat object as proxy-like and add probe keys lazily.
        maybeAddProxyProbeKeys();
        // Intentionally skip invoking getters to avoid side effects.
        continue;
      } else {
        continue; // non-enumerable data descriptor
      }
    } else {
      try {
        descriptorAttempts++;
        if (descriptorAttempts > MAX_DESCRIPTOR_ATTEMPTS) {
          throw new CircuitBreakerError("Descriptor attempt cap exceeded");
        }
        raw = value[k];
      } catch {
        continue; // skip inaccessible property
      }
    }

    if (
      raw === undefined ||
      typeof raw === "function" ||
      typeof raw === "symbol"
    )
      continue;

    // Enforce explicit rejection of BigInt values located inside objects
    if (typeof raw === "bigint") {
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }

    // Note: No special-case for 'constructor' beyond dropping above; tests
    // and sanitizer policy require ignoring it rather than throwing.

    // Local canonical value shape used to satisfy strict typing for assignments
    type CanonicalLocal =
      | null
      | string
      | number
      | boolean
      | Record<string, unknown>
      | readonly unknown[];

    const isCanonicalValue = (x: unknown): x is CanonicalLocal => {
      if (x === null) return true;
      const t = typeof x;
      if (t === "string" || t === "boolean" || t === "number") return true;
      if (Array.isArray(x)) return true;
      if (x && typeof x === "object") return true;
      return false;
    };

    type CanonResult =
      | { readonly present: true; readonly value: CanonicalLocal }
      | { readonly present: false };

    const computeCanon = (input: unknown): CanonResult => {
      if (input !== null && typeof input === "object") {
        const ex = cache.get(input);
        if (ex === PROCESSING)
          return Object.freeze({
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          });
        if (ex !== undefined)
          return Object.freeze({
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          });
      }
      const out = toCanonicalValueInternal(
        input,
        cache,
        depthRemaining === undefined ? undefined : depthRemaining - 1,
        deadline,
        circularPolicy,
      );
      if (out === undefined) return Object.freeze({ present: false });
      if (isCanonicalValue(out))
        return Object.freeze({ present: true, value: out });
      return Object.freeze({ present: false });
    };

    const canon = computeCanon(raw);

    if (!canon.present) continue;

    // Use safeAssign which validates key safety; rule flagged direct dynamic
    // assignment as a potential injection sink. Key list is derived from
    // ownKeys + controlled probe set and filtered via isForbiddenKey.
    safeAssign(result, k, canon.value);
  }
  cache.set(value as object, result);
  return result;
}

/**
 * Internal canonicalizer with cache-based cycle detection.
 */
function toCanonicalValueInternal(
  value: unknown,
  cache: WeakMap<object, unknown>,
  depthRemaining: number | undefined,
  deadline: number,
  circularPolicy: 'fail' | 'annotate',
): unknown {
  if (Date.now() > deadline) {
    throw new CanonicalizationTraversalError('Canonicalization time budget exceeded.');
  }
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new CanonicalizationDepthError('Canonicalization depth budget exceeded.');
  }
  // Handle special cases first
  if (value instanceof Date) return value.toISOString();

  // Convert TypedArray/DataView (that expose a numeric length and indices)
  // into plain arrays of numbers for nested positions. Top-level handling
  // is performed in toCanonicalValue.
  try {
    if (
      value !== null &&
      typeof value === "object" &&
      typeof ArrayBuffer !== "undefined" &&
      ArrayBuffer.isView(value as ArrayBufferView)
    ) {
      const length = (value as { readonly length?: number }).length;
      if (typeof length === "number") {
        return Array.from({ length }, (_unused, index) => {
          const v = (value as unknown as Record<number, unknown>)[index];
          return typeof v === "number" ? v : 0;
        });
      }
    }
  } catch (error) {
    // Log for development debugging but continue canonicalization
    secureDevelopmentLog(
      "warn",
      "toCanonicalValueInternal",
      "Object property enumeration failed",
      { error: error instanceof Error ? error.message : String(error) },
    );
    /* Continue with array/other handling */
  }

  // Array handling: delegate to array canonicalizer for cycle/dup detection
  if (Array.isArray(value)) {
    return canonicalizeArray(
      value as readonly unknown[],
      cache,
      depthRemaining,
      deadline,
      circularPolicy,
    );
  }

  if (isNonNullObject(value)) {
    return canonicalizeObject(
      value as Record<string, unknown>,
      cache,
      depthRemaining,
      deadline,
      circularPolicy,
    );
  }

  // Handle primitives and other types
  // BigInt must be rejected consistently as a security policy
  if (typeof value === "bigint") {
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }

  const primitiveResult = canonicalizePrimitive(value);
  if (primitiveResult !== undefined) return primitiveResult;

  return undefined;
}

/**
 * Converts any value to a canonical representation suitable for deterministic JSON serialization.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Security hardening requires multiple guarded branches and defensive checks
export function toCanonicalValue(value: unknown): unknown {
  // Reject top-level BigInt per security policy: BigInt is not supported
  // in payloads and must be rejected to avoid ambiguous JSON handling.
  if (typeof value === "bigint") {
    throw new InvalidParameterError(
      "BigInt values are not supported in payload/context.body.",
    );
  }
  // Special-case top-level TypedArray/ArrayBuffer: treat as exotic host objects
  // and canonicalize to empty object. Nested TypedArrays are handled in the
  // internal canonicalizer by converting to arrays of numbers.

  // Reject extremely large arrays early to avoid resource exhaustion.
  const { maxTopLevelArrayLength } = getCanonicalConfig();
  if (
    Array.isArray(value) &&
    (value as readonly unknown[]).length >= maxTopLevelArrayLength
  ) {
    throw new InvalidParameterError("Array too large for canonicalization.");
  }

  try {
    if (isNonNullObject(value)) {
      if (typeof ArrayBuffer !== "undefined") {
        const isView = (
          ArrayBuffer as unknown as {
            readonly isView?: (x: unknown) => boolean;
          }
        ).isView;
        if (isView?.(value) === true) {
          return Object.freeze({});
        }
        if (value instanceof ArrayBuffer) return Object.freeze({});
      }
    }
  } catch (error) {
    // Log for development debugging but continue canonicalization
    secureDevelopmentLog(
      "warn",
      "toCanonicalValue",
      "ArrayBuffer/TypedArray detection failed",
      { error: error instanceof Error ? error.message : String(error) },
    );
    /* Continue processing */
  }

  try {
    // Quick top-level forbidden-key check to fail fast on obvious prototype-pollution attempts
    if (isNonNullObject(value)) {
      try {
        // Avoid eagerly throwing on top-level forbidden keys; deeper traversal
        // will skip/remove forbidden keys consistently. This preserves API
        // expectations while still sanitizing prototype-polluting names.
        // Probe ownKeys to trigger potential proxy traps; capture length to avoid unused-var lint.
        const _ownKeysCount = Reflect.ownKeys(value).length;
        if (_ownKeysCount === -1) {
          // This branch is unreachable; it exists to make the read explicit and
          // satisfy no-unused-vars/no-unused-locals without using the `void` operator.
        }
      } catch (error) {
        // Log key enumeration failures but continue - exotic hosts may have special behavior
        secureDevelopmentLog(
          "warn",
          "toCanonicalValue",
          "Object key enumeration failed",
          { error: error instanceof Error ? error.message : String(error) },
        );
      }
    }
    const cfg = getCanonicalConfig();
    const initialDepth = cfg.maxDepth ?? undefined;
    const deadline = Date.now() + cfg.traversalTimeBudgetMs;
    const canonical = toCanonicalValueInternal(
      value,
      new WeakMap<object, unknown>(),
      initialDepth,
      deadline,
      cfg.circularPolicy,
    );
    // If the canonicalized result contains any nested __circular markers,
    // attach a non-enumerable top-level marker to aid detection without
    // altering the enumerable shape used by consumers.
    try {
      if (hasCircularSentinel(canonical)) {
        if (isNonNullObject(canonical)) {
          // eslint-disable-next-line functional/immutable-data -- Intentional addition of a non-enumerable marker for diagnostic purposes; does not affect consumer-visible enumerable shape
          Object.defineProperty(canonical, "__circular", {
            value: true,
            enumerable: false,
            configurable: false,
          });
        }
      }
    } catch {
      /* ignore */
    }
    return canonical;
  } catch (error) {
    if (error instanceof InvalidParameterError) throw error;
    // Depth budget exhaustion and circuit-breaker errors should be surfaced
    // to callers as InvalidParameterError so consumers can handle them
    // deterministically (tests and external callers depend on this shape).
    if (error instanceof RangeError || error instanceof CircuitBreakerError) {
      // Fail CLOSED: depth exhaustion or traversal resource limits must not
      // silently produce an empty object. Convert to a typed InvalidParameterError
      // so callers can handle deterministically per Pillar #1 and ASVS L3.
      throw makeInvalidParameterError(
        "Canonicalization depth budget exceeded.",
      );
    }
    // Ensure we always throw an Error object. If a non-Error was thrown,
    // wrap it to preserve the original message/inspectable value.
    if (error instanceof Error) throw error;
    throw makeInvalidParameterError(
      `Canonicalization failed: ${String(error)}`,
    );
  }
}

/**
 * Recursively scans a canonical value and returns true if any nested node
 * contains the `__circular` sentinel. This helper is extracted to reduce the
 * cognitive complexity of `toCanonicalValue` and to make the scanning logic
 * testable in isolation.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Separate helper is already extracted; remaining complexity is due to array/object traversal
export function hasCircularSentinel(
  v: unknown,
  depthRemaining?: number,
): boolean {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw makeDepthBudgetExceededError("hasCircularSentinel", 64);
  }
  if (isNonNullObject(v)) {
    try {
      if (Object.hasOwn(v, "__circular")) return true;
    } catch {
      /* ignore host failures */
    }
    if (Array.isArray(v)) {
      // Avoid relying on Array.prototype iteration since some arrays in this
      // module are constructed with a null prototype for pollution resistance.
      // Use index-based access to traverse elements safely.

      const n = (v as { readonly length: number }).length;
      // eslint-disable-next-line functional/no-let -- Loop counter is local to scanning logic
      for (let index = 0; index < n; index++) {
        const item = (v as unknown as { readonly [index: number]: unknown })[
          index
        ];
        if (
          hasCircularSentinel(
            item,
            depthRemaining === undefined ? undefined : depthRemaining - 1,
          )
        )
          return true;
      }
    } else {
      for (const k of Object.keys(v as Record<string, unknown>)) {
        if (
          hasCircularSentinel(
            (v as Record<string, unknown>)[k],
            depthRemaining === undefined ? undefined : depthRemaining - 1,
          )
        )
          return true;
      }
    }
  }
  return false;
}

/**
 * Deterministic JSON serialization with lexicographic key ordering and pruning
 * of null/undefined inside arrays that are values of object properties.
 */
export function safeStableStringify(value: unknown): string {
  // Fast pre-check: reject extremely large strings to avoid excessive memory
  // or CPU work during canonicalization / stringification. Use configured limit.
  const { maxStringLengthBytes } = getCanonicalConfig();
  if (
    typeof value === "string" &&
    SHARED_ENCODER.encode(value).length > maxStringLengthBytes
  ) {
    throw new InvalidParameterError("Payload too large for stable stringify.");
  }
  const canonical = toCanonicalValue(value);
  if (canonical === undefined) return "null";

  type Pos = "top" | "array" | "objectProp";

  // Render primitive JSON values and special cases. Returns undefined when the value
  // is not a primitive, allowing the caller to handle arrays/objects.
  const renderPrimitive = (v: unknown): string | undefined => {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "string") return JSON.stringify(v);
    if (t === "number") return Object.is(v, -0) ? "-0" : JSON.stringify(v);
    if (t === "boolean") return v ? "true" : "false";
    if (t === "bigint") {
      // Enforce BigInt rejection at stringification time as well to preserve
      // invariant across all layers (defense-in-depth per Security Constitution)
      throw new InvalidParameterError(
        "BigInt values are not supported in payload/context.body.",
      );
    }
    if (v === undefined) return "null";
    return undefined;
  };

  const arrayToJson = (array: readonly unknown[], pos: Pos): string => {
    // Avoid using Array.prototype methods; iterate by index for tamper resistance
    // eslint-disable-next-line functional/no-let -- Local accumulator string for efficient concatenation
    let rendered = "";
    // eslint-disable-next-line functional/no-let -- index-based iteration for tamper-resistance
    for (let index = 0, length = array.length; index < length; index++) {
      const element = (array as unknown as { readonly [k: number]: unknown })[
        index
      ];
      if (pos === "objectProp" && (element === null || element === undefined))
        continue;
      const part = stringify(element, "array");
      rendered = rendered === "" ? part : rendered + "," + part;
    }
    return "[" + rendered + "]";
  };

  const objectToJson = (objectValue: Record<string, unknown>): string => {
  const keys = Object.keys(objectValue).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    // eslint-disable-next-line functional/prefer-readonly-type -- Intentional mutable array for building JSON parts
    const parts: string[] = [];
    for (const k of keys) {
      const v = objectValue[k];
      if (v === undefined) continue; // drop undefined properties
      // eslint-disable-next-line functional/immutable-data -- Intentional array mutation for building JSON string parts
      parts.push(`${JSON.stringify(k)}:${stringify(v, "objectProp")}`);
    }
    return `{${parts.join(",")}}`;
  };

  const stringify = (value_: unknown, pos: Pos): string => {
    const prim = renderPrimitive(value_);
    if (prim !== undefined) return prim;

    if (Array.isArray(value_)) {
      return arrayToJson(value_ as readonly unknown[], pos);
    }

    if (value_ && typeof value_ === "object") {
      return objectToJson(value_ as Record<string, unknown>);
    }

    // Fallback for any other host values (should not occur after canonicalization)
    return JSON.stringify(value_);
  };

  return stringify(canonical, "top");
}

// ====================== Unicode Security Public API =======================

/**
 * Re-export Unicode security functions for public use with enhanced documentation.
 * These functions provide access to official Unicode 16.0.0 specification data
 * for identifier validation and confusables detection.
 *
 * For detailed documentation on Unicode data formats, profiles, and security
 * architecture, see: docs/User docs/unicode-data-format.md
 *
 * @example
 * ```typescript
 * // Configure Unicode security profile
 * setUnicodeSecurityConfig({
 *   dataProfile: 'standard',     // Use standard profile with confusables
 *   enableConfusablesDetection: true,
 *   maxInputLength: 2048
 * });
 *
 * // Validate identifier character
 * const status = getIdentifierStatus(0x61); // 'a' -> 'Allowed'
 *
 * // Check for confusable characters
 * const targets = getConfusableTargets('а'); // Cyrillic 'а' -> ['a']
 * const isRisky = isConfusable('а', 'a');    // true
 *
 * // Get profile statistics
 * const stats = getDataStats();
 * console.log(`Loaded ${stats.ranges} ranges, ${stats.confusables} confusables`);
 * ```
 */

/**
 * Get Unicode identifier validation ranges for the current profile.
 *
 * Returns an array of Unicode code point ranges that are allowed in identifiers
 * according to Unicode Technical Standard #39 (UTS #39).
 *
 * **Profile Behavior:**
 * - `minimal`: Basic identifier ranges (~391 ranges)
 * - `standard`: Full identifier ranges
 * - `complete`: Full identifier ranges (same as standard)
 *
 * **Performance:** O(1) - data is cached after first load
 *
 * **OWASP ASVS L3 Compliance:**
 * - V8.1.1: Data integrity verification via SHA-256
 * - V5.2.1: Input validation with official Unicode data
 *
 * @returns Array of Unicode ranges with start/end code points and status
 * @throws SecurityKitError if integrity verification fails
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/reports/tr39/} UTS #39 Unicode Security Mechanisms
 */
export { getIdentifierRanges } from "./generated/unicode-optimized-loader.ts";

/**
 * Check the identifier status of a Unicode code point.
 *
 * Returns the official UTS #39 status for the given code point:
 * - `'Allowed'`: Safe for use in identifiers
 * - `'Disallowed'`: Prohibited in identifiers
 * - `'Restricted'`: Contextually allowed (use with caution)
 * - `'Obsolete'`: Deprecated characters
 * - `undefined`: Not found in current profile data
 *
 * **Performance:** O(log n) binary search over identifier ranges
 *
 * **Security Notes:**
 * - Unknown code points default to 'Restricted' per UTS #39
 * - Use `'Allowed'` status for high-security validation
 * - `'Restricted'` may be acceptable depending on threat model
 *
 * @param codePoint - Unicode code point to check (0-0x10FFFF)
 * @returns Identifier status or undefined if not found
 * @throws InvalidParameterError if codePoint is invalid
 *
 * @example
 * ```typescript
 * const status = getIdentifierStatus(0x41);    // 'A' -> 'Allowed'
 * const status2 = getIdentifierStatus(0x200E); // LTR mark -> 'Disallowed'
 * ```
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/reports/tr39/#Identifier_Status} UTS #39 Identifier Status
 */
export { getIdentifierStatus } from "./generated/unicode-optimized-loader.ts";

/**
 * Get all Unicode confusable mappings for the current profile.
 *
 * Returns an array of confusable character mappings based on the official
 * Unicode confusablesSummary.txt file. Each mapping represents characters
 * that could be visually confused with each other.
 *
 * **Profile Behavior:**
 * - `minimal`: Empty array (no confusables for frontend optimization)
 * - `standard`: Curated high-risk confusables (~20,000 mappings)
 * - `complete`: Full confusables data (~17,271 official mappings)
 *
 * **Performance:** O(1) - data is cached after first load
 * **Memory Usage:** ~80KB for standard, ~82KB for complete profile
 *
 * **Use Cases:**
 * - Brand protection (domain spoofing detection)
 * - Security analysis and threat intelligence
 * - Internationalization validation
 * - Phishing detection in user-generated content
 *
 * @returns Array of source→target confusable mappings
 * @throws SecurityKitError if integrity verification fails
 *
 * @example
 * ```typescript
 * const confusables = getConfusables();
 * console.log(`${confusables.length} confusable mappings loaded`);
 *
 * // Find specific confusables
 * const cyrillicConfusables = confusables.filter(c =>
 *   c.source >= '\u0400' && c.source <= '\u04FF'
 * );
 * ```
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/Public/16.0.0/ucd/confusablesSummary.txt} Official confusables data
 */
/**
 * Get all Unicode confusable mappings for the current profile.
 *
 * Returns an array of confusable character mappings based on the official
 * Unicode confusablesSummary.txt file. Each mapping represents characters
 * that could be visually confused with each other.
 *
 * **Profile Behavior:**
 * - `minimal`: Empty array (no confusables for frontend optimization)
 * - `standard`: Curated high-risk confusables (~20,000 mappings)
 * - `complete`: Full confusables data (~17,271 official mappings)
 *
 * **Performance:** O(1) - data is cached after first load
 * **Memory Usage:** ~80KB for standard, ~82KB for complete profile
 *
 * **Use Cases:**
 * - Brand protection (domain spoofing detection)
 * - Security analysis and threat intelligence
 * - Internationalization validation
 * - Phishing detection in user-generated content
 *
 * @returns Array of source→target confusable mappings
 * @throws SecurityKitError if integrity verification fails
 *
 * @example
 * ```typescript
 * const confusables = getConfusables();
 * console.log(`${confusables.length} confusable mappings loaded`);
 *
 * // Find specific confusables
 * const cyrillicConfusables = confusables.filter(c =>
 *   c.source >= '\u0400' && c.source <= '\u04FF'
 * );
 * ```
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/Public/16.0.0/ucd/confusablesSummary.txt} Official confusables data
 */
export { getConfusables } from "./generated/unicode-optimized-loader.ts";

/**
 * Check if two characters are confusable with each other.
 *
 * Uses official Unicode confusables data to determine if two characters
 * could be visually confused. Checks both directions of the mapping.
 *
 * **Input Normalization:** Both characters are normalized to NFC before lookup
 * **Case Sensitivity:** Case-sensitive comparison (use toLowerCase() if needed)
 * **Performance:** O(n) where n = number of confusables (future: O(log n) with indexing)
 *
 * **Security Applications:**
 * - Homograph attack detection
 * - Brand/domain spoofing prevention
 * - User input validation
 * - Content moderation
 *
 * @param char1 - First character to compare
 * @param char2 - Second character to compare
 * @returns true if characters are confusable, false otherwise
 * @throws InvalidParameterError if characters are invalid
 *
 * @example
 * ```typescript
 * // Cyrillic 'а' vs Latin 'a' (classic homograph attack)
 * const isRisky = isConfusable('а', 'a');  // true
 *
 * // Greek 'ο' vs Latin 'o'
 * const isRisky2 = isConfusable('ο', 'o'); // true
 *
 * // Same characters
 * const same = isConfusable('a', 'a');     // false
 * ```
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/reports/tr39/#Confusable_Detection} UTS #39 Confusable Detection
 */
export { isConfusable } from "./generated/unicode-optimized-loader.ts";

/**
 * Get all confusable target characters for a given source character.
 *
 * Returns an array of characters that could be visually confused with the
 * input character, based on official Unicode confusables data.
 *
 * **Input Normalization:** Input character is normalized to NFC before lookup
 * **Performance:** O(n) linear search (future: O(log n) with indexing)
 * **Ordering:** Results are in the order they appear in confusables data
 *
 * **Risk Assessment Applications:**
 * - Generate alternative spellings for brand protection
 * - Identify potential spoofing vectors
 * - Security analysis and penetration testing
 * - Content similarity analysis
 *
 * @param char - Source character to find confusable targets for
 * @returns Array of confusable target characters (may be empty)
 * @throws InvalidParameterError if char is invalid
 *
 * @example
 * ```typescript
 * // Find confusables for Latin 'a'
 * const targets = getConfusableTargets('a');
 * // Returns: ['а', 'α', 'ａ', ...] (Cyrillic, Greek, fullwidth variants)
 *
 * // Check for any confusables
 * const hasConfusables = targets.length > 0;
 *
 * // Generate brand protection rules
 * const brandName = 'paypal';
 * for (const char of brandName) {
 *   const variants = getConfusableTargets(char);
 *   if (variants.length > 0) {
 *     console.log(`'${char}' can be confused with: ${variants.join(', ')}`);
 *   }
 * }
 * ```
 *
 * @since 1.0.0
 * @see {@link https://unicode.org/reports/tr39/#Confusable_Detection} UTS #39 Confusable Detection
 */
export { getConfusableTargets } from "./generated/unicode-optimized-loader.ts";

/**
 * Get statistics about the currently loaded Unicode data profile.
 *
 * Provides metrics about the Unicode data currently in memory, useful for
 * monitoring, debugging, and performance analysis.
 *
 * **Profile Statistics:**
 * - `minimal`: ~391 ranges, 0 confusables, ~877 bytes
 * - `standard`: ~391 ranges, ~20K confusables, ~80KB
 * - `complete`: ~391 ranges, ~17K confusables, ~82KB
 *
 * **Performance:** O(1) - calculates from cached data
 *
 * **Monitoring Applications:**
 * - Profile validation in production
 * - Memory usage analysis
 * - Data loading verification
 * - Performance benchmarking
 *
 * @returns Unicode data statistics object
 * @throws SecurityKitError if data loading failed
 *
 * @example
 * ```typescript
 * const stats = getDataStats();
 * console.log(`Profile loaded: ${stats.ranges} ranges, ${stats.confusables} confusables`);
 * console.log(`Memory usage: ${stats.totalBytes} bytes`);
 *
 * // Verify expected profile
 * const config = getUnicodeSecurityConfig();
 * if (config.dataProfile === 'standard' && stats.confusables === 0) {
 *   console.warn('Standard profile expected but no confusables loaded');
 * }
 * ```
 *
 * @since 1.0.0
 */
export { getDataStats } from "./generated/unicode-optimized-loader.ts";

/**
 * Get the current Unicode security configuration.
 *
 * Returns the current configuration controlling Unicode data loading,
 * validation behavior, and performance characteristics.
 *
 * **Configuration Properties:**
 * - `dataProfile`: Which Unicode dataset to load (minimal/standard/complete)
 * - `lazyLoad`: Whether to load data on-demand vs eagerly
 * - `maxInputLength`: Maximum characters for Unicode validation (DoS protection)
 * - `enableConfusablesDetection`: Enable/disable confusables analysis
 * - `enableValidationCache`: Cache validation results for performance
 *
 * **Thread Safety:** Configuration is immutable (frozen object)
 * **Performance:** O(1) - returns cached configuration copy
 *
 * @returns Current Unicode security configuration (frozen)
 *
 * @example
 * ```typescript
 * const config = getUnicodeSecurityConfig();
 * console.log(`Current profile: ${config.dataProfile}`);
 * console.log(`Confusables detection: ${config.enableConfusablesDetection}`);
 * console.log(`Max input length: ${config.maxInputLength} characters`);
 *
 * // Conditional behavior based on configuration
 * if (config.dataProfile === 'minimal') {
 *   console.log('Using minimal profile - no confusables detection');
 * }
 * ```
 *
 * @since 1.0.0
 * @see {@link setUnicodeSecurityConfig} To modify configuration
 * @see {@link file://./docs/User docs/unicode-data-format.md} Unicode data format documentation
 */
export { getUnicodeSecurityConfig } from "./config.ts";

/**
 * Update Unicode security configuration.
 *
 * Modifies the Unicode security configuration to control data loading,
 * validation behavior, and performance characteristics. Configuration
 * can only be changed before the crypto state is sealed.
 *
 * **Profile Selection Guide:**
 * - `minimal`: Frontend/mobile apps - basic validation only (~877 bytes)
 * - `standard`: Backend/servers - full validation with curated confusables (~80KB)
 * - `complete`: Security research - comprehensive confusables dataset (~82KB)
 *
 * **Performance Considerations:**
 * - `lazyLoad: true`: Faster startup, async overhead on first use
 * - `lazyLoad: false`: Slower startup, predictable runtime performance
 * - `enableValidationCache: true`: Memory vs CPU tradeoff
 *
 * **Security Considerations:**
 * - Higher `maxInputLength`: Greater DoS attack surface
 * - `enableConfusablesDetection: false`: Reduced attack detection capability
 * - Profile changes require application restart to fully take effect
 *
 * @param config - Partial configuration object to merge with current settings
 * @throws InvalidConfigurationError if crypto state is sealed
 * @throws InvalidParameterError if configuration values are invalid
 *
 * @example
 * ```typescript
 * // Frontend-optimized configuration
 * setUnicodeSecurityConfig({
 *   dataProfile: 'minimal',
 *   lazyLoad: true,
 *   enableConfusablesDetection: false,
 *   maxInputLength: 1024
 * });
 *
 * // Backend production configuration
 * setUnicodeSecurityConfig({
 *   dataProfile: 'standard',
 *   lazyLoad: false,
 *   enableConfusablesDetection: true,
 *   maxInputLength: 4096,
 *   enableValidationCache: false // Avoid memory overhead
 * });
 *
 * // Security research configuration
 * setUnicodeSecurityConfig({
 *   dataProfile: 'complete',
 *   enableConfusablesDetection: true,
 *   maxInputLength: 8192
 * });
 * ```
 *
 * @since 1.0.0
 * @see {@link getUnicodeSecurityConfig} To read current configuration
 * @see {@link file://./docs/User docs/unicode-data-format.md} Unicode data format documentation
 */
export { setUnicodeSecurityConfig, sealUnicodeSecurityConfig } from "./config.ts";

/**
 * Export Unicode types for public use.
 *
 * These types support the Unicode security API and provide type safety
 * for applications using the Unicode validation functions.
 *
 * @since 1.0.0
 */
export type {
  UnicodeProfile,
  IdentifierStatus,
  UnicodeRangeEntry,
  UnicodeConfusableEntry,
  UnicodeDataStats,
} from "./generated/unicode-optimized-loader.ts";

export type { UnicodeSecurityConfig } from "./config.ts";
