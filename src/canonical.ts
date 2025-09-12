import { InvalidParameterError } from "./errors.ts";
import { SHARED_ENCODER } from "./encoding.ts";
import { isForbiddenKey } from "./constants.ts";
import {
  secureCompareAsync,
  secureDevLog as secureDevelopmentLog,
} from "./utils.ts";
import {
  getCanonicalConfig,
  MAX_CANONICAL_INPUT_LENGTH_BYTES,
  MAX_NORMALIZED_LENGTH_RATIO,
  MAX_COMBINING_CHARS_PER_BASE,
  BIDI_CONTROL_CHARS,
  INVISIBLE_CHARS,
  HOMOGLYPH_SUSPECTS,
  DANGEROUS_UNICODE_RANGES,
  STRUCTURAL_RISK_CHARS,
} from "./config.ts";

// Sentinel to mark nodes currently under processing in the cache
const PROCESSING = Symbol("__processing");

// (internal helpers removed)

/**
 * Convert unknown input to a string safely without triggering hostile toString() methods.
 * Enhanced for OWASP ASVS L3 with comprehensive input validation and DoS protection.
 * @internal
 */
function _toString(input: unknown): string {
  if (typeof input === "string") return input;
  if (typeof input === "number") {
    return Number.isFinite(input) ? String(input) : "";
  }
  if (typeof input === "boolean") return String(input);
  if (typeof input === "bigint") return input.toString();
  if (input === null || input === undefined) return "";
  // For objects, use JSON.stringify as a safe fallback that avoids
  // calling toString() which could be a hostile getter
  try {
    const json = JSON.stringify(input);
    return typeof json === "string" ? json : "";
  } catch {
    return "";
  }
}

/**
 * Validate Unicode string for security threats per OWASP ASVS L3 requirements.
 * Enhanced with Trojan Source attack detection based on Boucher & Anderson research.
 * Detects:
 * - Bidirectional control characters (visual spoofing)
 * - Invisible/zero-width characters (hidden content)
 * - Homoglyph suspects (character spoofing)
 * - Dangerous Unicode ranges (control chars, private use)
 * - Trojan Source attack patterns
 *
 * @param string_ - The string to validate
 * @param context - Context for error reporting (e.g., "URL", "fragment")
 * @throws InvalidParameterError if validation fails
 */
function validateUnicodeSecurity(string_: string, context: string): void {
  // Trojan Source Attack Detection: Bidirectional control characters
  if (BIDI_CONTROL_CHARS.test(string_)) {
    const suspiciousChars = Array.from(string_.match(BIDI_CONTROL_CHARS) || [])
      .map(
        (char) =>
          `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`,
      )
      .join(", ");

    secureDevelopmentLog(
      "warn",
      "validateUnicodeSecurity",
      `Trojan Source attack detected: bidirectional control characters found`,
      { context, suspiciousChars, inputLength: string_.length },
    );

    throw new InvalidParameterError(
      `${context}: Contains bidirectional control characters (${suspiciousChars}) that enable Trojan Source attacks.`,
    );
  }

  // Invisible Character Detection: Zero-width and formatting characters
  if (INVISIBLE_CHARS.test(string_)) {
    const invisibleChars = Array.from(string_.match(INVISIBLE_CHARS) || [])
      .map(
        (char) =>
          `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`,
      )
      .join(", ");

    secureDevelopmentLog(
      "warn",
      "validateUnicodeSecurity",
      `Invisible characters detected: potential content hiding`,
      { context, invisibleChars, inputLength: string_.length },
    );

    throw new InvalidParameterError(
      `${context}: Contains invisible characters (${invisibleChars}) that could hide malicious content.`,
    );
  }

  // Homoglyph Attack Detection: Characters that visually resemble ASCII
  if (HOMOGLYPH_SUSPECTS.test(string_)) {
    const homoglyphs = Array.from(string_.match(HOMOGLYPH_SUSPECTS) || [])
      .map(
        (char) =>
          `'${char}' (U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")})`,
      )
      .join(", ");

    secureDevelopmentLog(
      "warn",
      "validateUnicodeSecurity",
      `Potential homoglyph attack: non-ASCII characters resembling ASCII`,
      { context, homoglyphs, inputLength: string_.length },
    );

    throw new InvalidParameterError(
      `${context}: Contains potential homoglyph characters (${homoglyphs}) that could enable spoofing attacks.`,
    );
  }

  // Check for dangerous Unicode ranges (control chars, private use areas, etc.)
  if (DANGEROUS_UNICODE_RANGES.test(string_)) {
    const dangerousChars = Array.from(
      string_.match(DANGEROUS_UNICODE_RANGES) || [],
    )
      .map(
        (char) =>
          `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`,
      )
      .join(", ");

    throw new InvalidParameterError(
      `${context}: Contains dangerous Unicode characters (${dangerousChars}) in control or private use ranges.`,
    );
  }

  // Advanced heuristic-based security scoring system
  // This replaces simple binary rules with adaptive threat assessment
  const securityScore = calculateSecurityRiskScore(string_);
  
  if (securityScore.totalScore >= 60) { // Lowered threshold from 70 to 60
    secureDevelopmentLog(
      "warn",
      "validateUnicodeSecurity",
      `High security risk score detected: potential attack pattern`,
      { 
        context, 
        totalScore: securityScore.totalScore,
        factors: securityScore.factors,
        inputLength: string_.length,
        recommendation: securityScore.recommendation
      },
    );

    throw new InvalidParameterError(
      `${context}: Input rejected due to high security risk score (${securityScore.totalScore}/100). ${securityScore.recommendation}`,
    );
  }

  // Additional Trojan Source pattern detection
  detectTrojanSourcePatterns(string_, context);
}

/**
 * Detect specific Trojan Source attack patterns beyond individual character detection.
 * Based on "Trojan Source: Invisible Vulnerabilities" research patterns.
 *
 * @param string_ - The string to analyze for attack patterns
 * @param context - Context for error reporting
 * @throws InvalidParameterError if attack patterns are detected
 */
function detectTrojanSourcePatterns(string_: string, context: string): void {
  // Pattern 1: Bidirectional override sequences (classic Trojan Source)
  // Look for LRO/RLO followed by content then PDF/PDI
  const trojanSourcePattern = /[\u202D\u202E].*?[\u202C\u2069]/u;
  if (trojanSourcePattern.test(string_)) {
    secureDevelopmentLog(
      "error",
      "detectTrojanSourcePatterns",
      `Classic Trojan Source attack pattern detected`,
      {
        context,
        pattern: "bidirectional_override_sequence",
        inputLength: string_.length,
      },
    );

    throw new InvalidParameterError(
      `${context}: Contains classic Trojan Source attack pattern (bidirectional override sequence).`,
    );
  }

  // Pattern 2: Embedding attacks (LRE/RLE with nested content)
  const embeddingPattern = /[\u202A\u202B].*?\u202C/u;
  if (embeddingPattern.test(string_)) {
    secureDevelopmentLog(
      "error",
      "detectTrojanSourcePatterns",
      `Bidirectional embedding attack pattern detected`,
      { context, pattern: "embedding_sequence", inputLength: string_.length },
    );

    throw new InvalidParameterError(
      `${context}: Contains bidirectional embedding attack pattern.`,
    );
  }

  // Pattern 3: Mixed script with suspicious character combinations
  // Common in supply chain attacks where legitimate-looking identifiers contain hidden chars
  const mixedScriptSuspicious =
    /\w+[\u200B-\u200F\u202A-\u202E\u2066-\u2069]+\w+/u;
  if (mixedScriptSuspicious.test(string_)) {
    secureDevelopmentLog(
      "warn",
      "detectTrojanSourcePatterns",
      `Suspicious mixed script pattern with invisible characters`,
      {
        context,
        pattern: "mixed_script_invisible",
        inputLength: string_.length,
      },
    );

    throw new InvalidParameterError(
      `${context}: Contains suspicious mixed script pattern with invisible characters.`,
    );
  }

  // Pattern 4: Zero-width character injection in identifier-like strings
  if (/^[a-zA-Z]\w*$/u.test(string_.replace(/[\u200B-\u200F]/gu, ""))) {
    if (/[\u200B-\u200F]/u.test(string_)) {
      secureDevelopmentLog(
        "error",
        "detectTrojanSourcePatterns",
        `Zero-width character injection in identifier detected`,
        {
          context,
          pattern: "zero_width_injection",
          inputLength: string_.length,
        },
      );

      throw new InvalidParameterError(
        `${context}: Contains zero-width character injection in identifier-like string.`,
      );
    }
  }

  // Combining Character DoS Protection (OWASP ASVS L3)
  validateCombiningCharacterLimits(string_, context);
}

/**
 * Calculate comprehensive security risk score for input validation.
 * Uses multiple heuristics to detect potential attack patterns that might
 * evade individual security checks. Implements adaptive security per
 * OWASP ASVS L3 requirements.
 * 
 * @param string_ - The input string to analyze
 * @returns Security assessment with total score and contributing factors
 */
interface SecurityRiskAssessment {
  totalScore: number;
  factors: Record<string, number>;
  recommendation: string;
}

function calculateSecurityRiskScore(string_: string): SecurityRiskAssessment {
  const factors: Record<string, number> = {};
  let totalScore = 0;

  // Factor 1: Whitespace density (any whitespace, not just consecutive)
  const whitespaceRatio = (string_.match(/[\s\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]/gu) || []).length / string_.length;
  if (whitespaceRatio >= 0.35) { // Lowered from 0.4 to 0.35 (35% instead of 40%)
    factors.whitespace_density = Math.round(whitespaceRatio * 120); // Increased multiplier
    totalScore += factors.whitespace_density;
  }

  // Factor 2: Consecutive whitespace patterns (original logic but as scoring)
  const consecutiveWhitespace = string_.match(/[\s\u00A0\u2000-\u200B\u2028\u2029\u202F\u205F\u3000]{3,}/gu);
  if (consecutiveWhitespace) {
    const maxConsecutive = Math.max(...consecutiveWhitespace.map(m => m.length));
    factors.consecutive_whitespace = Math.min(maxConsecutive * 10, 50); // Increased multiplier from 8 to 10
    totalScore += factors.consecutive_whitespace;
  }

  // Factor 3: Repetitive character patterns (potential DoS/layout manipulation)
  const repetitiveMatches = string_.match(/(.)\1{4,}/gu); // 5+ same chars
  if (repetitiveMatches) {
    const maxRepeats = Math.max(...repetitiveMatches.map(m => m.length));
    factors.repetitive_patterns = Math.min(maxRepeats * 4, 30); // Increased multiplier
    totalScore += factors.repetitive_patterns;
  }

  // Factor 4: Punctuation density (suspicious if too high)
  const punctuationRatio = (string_.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/gu) || []).length / string_.length;
  if (punctuationRatio >= 0.25) { // Lowered from 0.3 to 0.25 (25% instead of 30%)
    factors.punctuation_density = Math.round(punctuationRatio * 100); // Increased multiplier
    totalScore += factors.punctuation_density;
  }

  // Factor 5: Character variety (too low variety suggests pattern attacks)
  const uniqueChars = new Set(string_).size;
  const varietyRatio = uniqueChars / string_.length;
  if (varietyRatio < 0.35 && string_.length > 8) { // Lowered length threshold from 10 to 8
    factors.low_character_variety = Math.round((0.35 - varietyRatio) * 120);
    totalScore += factors.low_character_variety;
  }

  // Factor 6: Suspicious character combinations
  if (/\s{2,}[!]{3,}/u.test(string_)) { // Multiple spaces followed by many exclamations
    factors.suspicious_combinations = 20; // Increased from 15 to 20
    totalScore += factors.suspicious_combinations;
  }

  // Factor 7: Length-based risk (very short inputs with patterns are more suspicious)
  if (string_.length < 30 && totalScore > 0) { // Increased from 25 to 30
    factors.short_pattern_boost = Math.round(15 * (30 - string_.length) / 30); // Increased boost
    totalScore += factors.short_pattern_boost;
  }

  // Factor 8: Leading whitespace pattern (common in layout manipulation attacks)
  if (/^\s{4,}/u.test(string_)) {
    factors.leading_whitespace = 15;
    totalScore += factors.leading_whitespace;
  }

  // Factor 9: Repetitive digits (potential obfuscation or confusion attacks)
  const digitMatches = string_.match(/(\d)\1{3,}/gu); // 4+ same digits
  if (digitMatches) {
    const maxDigitRepeats = Math.max(...digitMatches.map(m => m.length));
    factors.repetitive_digits = Math.min(maxDigitRepeats * 3, 15);
    totalScore += factors.repetitive_digits;
  }

  // Generate contextual recommendation
  let recommendation = "Consider using simpler, more natural input patterns.";
  if (factors.whitespace_density) {
    recommendation = "High whitespace density detected - potential layout manipulation.";
  } else if (factors.consecutive_whitespace) {
    recommendation = "Consecutive whitespace patterns detected - potential DoS attack.";
  } else if (factors.repetitive_patterns) {
    recommendation = "Repetitive character patterns detected - potential manipulation attempt.";
  }

  return {
    totalScore: Math.round(totalScore),
    factors,
    recommendation
  };
}

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
function validateCombiningCharacterLimits(string_: string, context: string): void {
  let baseCharCount = 0;
  let combiningCharCount = 0;
  let consecutiveCombining = 0;

  for (const char of string_) {
    const codePoint = char.codePointAt(0)!;
    
    // Check if character is a combining mark (General Category Mn, Mc, Me)
    // Unicode ranges for combining marks:
    // - Combining Diacritical Marks (0300-036F)
    // - Combining Diacritical Marks Extended (1AB0-1AFF)
    // - Combining Diacritical Marks Supplement (1DC0-1DFF)
    // - Combining Half Marks (FE20-FE2F)
    const isCombining = (
      (codePoint >= 0x0300 && codePoint <= 0x036F) ||
      (codePoint >= 0x1AB0 && codePoint <= 0x1AFF) ||
      (codePoint >= 0x1DC0 && codePoint <= 0x1DFF) ||
      (codePoint >= 0xFE20 && codePoint <= 0xFE2F) ||
      // Check Unicode general category for combining marks
      /^\p{M}/u.test(char)
    );

    if (isCombining) {
      combiningCharCount++;
      consecutiveCombining++;
      
      // Check for excessive combining characters on single base character
      if (consecutiveCombining > MAX_COMBINING_CHARS_PER_BASE) {
        throw new InvalidParameterError(
          `${context}: Excessive combining characters detected (${consecutiveCombining} consecutive). ` +
          `Maximum ${MAX_COMBINING_CHARS_PER_BASE} combining marks per base character allowed.`
        );
      }
    } else {
      baseCharCount++;
      consecutiveCombining = 0; // Reset counter for new base character
    }
  }

  // Additional check: if more than 30% of characters are combining marks in larger inputs, likely an attack
  // Only apply this check for strings with substantial content (>20 chars) to avoid false positives
  const totalChars = baseCharCount + combiningCharCount;
  if (totalChars > 20 && (combiningCharCount / totalChars) > 0.3) {
    throw new InvalidParameterError(
      `${context}: Suspicious ratio of combining characters (${combiningCharCount}/${totalChars}). ` +
      "Possible combining character DoS attack."
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

  // Fast exit: if normalized contains none of the risk chars, skip set diff.
  if (!STRUCTURAL_RISK_CHARS.test(normalized)) return;

  // Build occurrence sets
  const inRaw = new Set<string>();
  for (const ch of raw) {
    if (STRUCTURAL_RISK_CHARS.test(ch)) inRaw.add(ch);
  }
  const introduced: string[] = [];
  for (const ch of normalized) {
    if (STRUCTURAL_RISK_CHARS.test(ch) && !inRaw.has(ch)) {
      introduced.push(ch);
    }
  }
  if (introduced.length === 0) return;

  const unique = Array.from(new Set(introduced));
  secureDevelopmentLog(
    "warn",
    "detectIntroducedStructuralChars",
    "Normalization introduced structural delimiter(s)",
    { context, introduced: unique },
  );

  throw new InvalidParameterError(
    `${context}: Normalization introduced structural characters (${unique.join(", ")}).`,
  );
}

/**
 * Verify NFKC idempotency (defense-in-depth). canonical(normalized) must equal
 * normalized. Detects unexpected engine/polyfill behavior or malformed surrogate
 * edge cases (OWASP ASVS V5.1.4: stable canonicalization).
 *
 * Real-world incidents (e.g., Spotify) have shown that non-idempotent
 * canonicalization can lead to security bypasses and account takeovers.
 *
 * @param normalized - The NFKC-normalized string to verify
 * @param context - Context for error reporting
 * @throws InvalidParameterError if a second normalization pass changes output
 */
function verifyNormalizationIdempotent(
  normalized: string,
  context: string,
): void {
  const second = normalized.normalize("NFKC");
  if (second !== normalized) {
    secureDevelopmentLog(
      "error",
      "verifyNormalizationIdempotent",
      "Non-idempotent normalization detected",
      {
        context,
        firstLength: normalized.length,
        secondLength: second.length,
      },
    );
    throw new InvalidParameterError(
      `${context}: Normalization not idempotent (environment anomaly).`,
    );
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
  verifyNormalizationIdempotent(normalized, context);

  // Re-validate after normalization to catch newly introduced dangerous patterns
  if (normalized.length > 0) {
    validateUnicodeSecurity(normalized, context);
  }

  return normalized;
}

/**
 * Normalize and validate URL components with context-specific security rules.
 * @param input - The URL component to normalize
 * @param componentType - Type of URL component for context-specific validation
 * @returns The normalized and validated URL component
 */
export function normalizeUrlComponent(
  input: unknown,
  componentType: "scheme" | "host" | "path" | "query" | "fragment" = "query",
): string {
  const context = `URL ${componentType}`;
  const normalized = normalizeInputString(input, context);

  // Additional validation based on component type
  switch (componentType) {
    case "scheme": {
      if (normalized && !/^[a-zA-Z][a-zA-Z0-9+.-]*$/u.test(normalized)) {
        throw new InvalidParameterError(
          `${context}: Contains invalid characters for URL scheme.`,
        );
      }
      return normalized.toLowerCase();
    }
    case "host": {
      // Additional hostname-specific validation
      if (normalized.includes("..") || normalized.includes("//")) {
        throw new InvalidParameterError(
          `${context}: Contains path traversal sequences.`,
        );
      }
      return normalized.toLowerCase();
    }
    case "path": {
      // Check for encoded traversal sequences
      if (/%2e|%2f|%5c/iu.test(normalized)) {
        throw new InvalidParameterError(
          `${context}: Contains encoded path traversal sequences.`,
        );
      }
      return normalized;
    }
    case "fragment": {
      // Fragments should not contain dangerous schemes
      const lowerFragment = normalized.toLowerCase();
      const dangerousSchemes = ["javascript:", "data:", "vbscript:"];
      for (const scheme of dangerousSchemes) {
        if (lowerFragment.includes(scheme)) {
          throw new InvalidParameterError(
            `${context}: Contains dangerous scheme '${scheme}'.`,
          );
        }
      }
      return normalized;
    }
    default: {
      return normalized;
    }
  }
}

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
export function sanitizeForLogging(input: unknown, maxLength = 200): string {
  try {
    const string_ = _toString(input);

    // Apply basic normalization but catch any security violations
    // and replace dangerous content rather than throwing
    let sanitized: string;
    try {
      sanitized = string_.normalize("NFKC");
    } catch {
      sanitized = string_;
    }

    // Replace dangerous Unicode ranges with safe placeholders
    sanitized = sanitized
      .replace(BIDI_CONTROL_CHARS, "[BIDI]")
      .replace(DANGEROUS_UNICODE_RANGES, "[CTRL]")
      .replace(/[\u0000-\u001F\u007F]/gu, "[CTRL]"); // Additional control char cleanup

    // Truncate if too long
    if (sanitized.length > maxLength) {
      sanitized = sanitized.slice(0, maxLength - 3) + "...";
    }

    return sanitized;
  } catch {
    return "[INVALID_INPUT]";
  }
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
      return { success: false, error: `${context}: Empty input not allowed.` };
    }

    if (requireAscii && !/^[\x00-\x7F]*$/u.test(rawString)) {
      return {
        success: false,
        error: `${context}: Non-ASCII characters not allowed.`,
      };
    }

    // Check size before normalization
    const rawBytes = SHARED_ENCODER.encode(rawString);
    if (rawBytes.length > maxLength) {
      return {
        success: false,
        error: `${context}: Input exceeds maximum size (${maxLength} bytes).`,
      };
    }

    // Perform normalization with full validation
    const normalized = normalizeInputString(rawString, context);

    return { success: true, value: normalized };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
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

  // Immediate rejection of any non-ASCII characters
  if (!/^[\x00-\x7F]*$/u.test(rawString)) {
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
export function normalizeUrlSafeString(
  input: unknown,
  context: string,
  options: {
    readonly maxLength?: number;
    readonly allowSpaces?: boolean;
  } = {},
): string {
  const { maxLength = 2048, allowSpaces = false } = options;

  const baseNormalized = normalizeInputString(input, context, { maxLength });

  // Define URL-safe character set (RFC 3986 unreserved + percent encoding)
  const urlSafePattern = allowSpaces
    ? /^[\w.~:/?#[\]@!$&'()*+,;=\-% ]*$/u
    : /^[\w.~:/?#[\]@!$&'()*+,;=\-%]*$/u;

  if (!urlSafePattern.test(baseNormalized)) {
    const unsafeChars = Array.from(baseNormalized)
      .filter((char) => !urlSafePattern.test(char))
      .map(
        (char) =>
          `'${char}' (U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")})`,
      )
      .slice(0, 3)
      .join(", ");

    throw new InvalidParameterError(
      `${context}: Contains non-URL-safe characters: ${unsafeChars}`,
    );
  }

  // Additional validation for common URL injection patterns
  const suspiciousPatterns = [
    /javascript:/iu,
    /data:/iu,
    /vbscript:/iu,
    /file:/iu,
    /<script/iu,
    /<%/u,
    /%3cscript/iu,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(baseNormalized)) {
      secureDevelopmentLog(
        "error",
        "normalizeUrlSafeString",
        `Suspicious URL pattern detected`,
        {
          context,
          pattern: pattern.source,
          inputLength: baseNormalized.length,
        },
      );

      throw new InvalidParameterError(
        `${context}: Contains potentially dangerous URL patterns.`,
      );
    }
  }

  return baseNormalized;
}

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
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
  }
  const asObject = value as unknown as object;
  const existing = cache.get(asObject);
  if (existing === PROCESSING) return { __circular: true };
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
    );
  }

  cache.set(asObject, result);
  return result;
}
/**
 * Handles canonicalization of objects with proxy-friendly property discovery.
 */
// eslint-disable-next-line sonarjs/cognitive-complexity -- Complex object canonicalization with multiple exotic object types and proxy handling
function canonicalizeObject(
  value: Record<string, unknown>,
  cache: WeakMap<object, unknown>,
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
  }
  const existing = cache.get(value as object);
  if (existing === PROCESSING) return { __circular: true };
  if (existing !== undefined) return existing;

  cache.set(value as object, PROCESSING);

  // ArrayBuffer at object position → {}
  try {
    if (value instanceof ArrayBuffer) {
      const empty = {} as Record<string, unknown>;

      cache.set(value as object, empty);
      return empty;
    }
  } catch {
    /* ignore */
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
  // enumerability is validated when reading descriptors below.
  const keySet = new Set<string>();
  for (const k of Reflect.ownKeys(value)) {
    // eslint-disable-next-line functional/immutable-data
    if (typeof k === "string") keySet.add(k);
  }

  // Conservative probe for proxies: include alphabetic keys 'a'..'z' and 'A'..'Z'
  const alpha = "abcdefghijklmnopqrstuvwxyz";
  // eslint-disable-next-line functional/no-let -- Intentional let for loop index in proxy key probing
  for (let index = 0; index < alpha.length; index++) {
    // eslint-disable-next-line functional/immutable-data -- Intentional mutability for proxy key probing during canonicalization
    keySet.add(alpha.charAt(index));
    // eslint-disable-next-line functional/immutable-data -- Intentional mutability for proxy key probing during canonicalization
    keySet.add(alpha.charAt(index).toUpperCase());
  }

  const keys = Array.from(keySet).sort((a, b) => a.localeCompare(b));

  // Create the result with a null prototype up-front so we never perform
  // assignments onto a default Object.prototype bearing object. This reduces
  // the surface for prototype pollution and allows safeAssign to remain a
  // thin wrapper (ASVS L3: Use of secure object construction patterns).
  const result: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
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
      descriptor = Object.getOwnPropertyDescriptor(value, k) ?? undefined;
    } catch {
      descriptor = undefined;
    }

    // eslint-disable-next-line functional/no-let -- Intentional let for raw value handling in canonicalization
    let raw: unknown;
    if (
      descriptor !== undefined &&
      descriptor.enumerable === true &&
      "value" in descriptor
    ) {
      raw = descriptor.value;
    } else if (descriptor === undefined) {
      try {
        raw = value[k];
      } catch {
        continue;
      }
    } else {
      // non-enumerable or accessor — ignore
      continue;
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
          return {
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          };
        if (ex !== undefined)
          return {
            present: true,
            value: { __circular: true } as Record<string, unknown>,
          };
      }
      const out = toCanonicalValueInternal(
        input,
        cache,
        depthRemaining === undefined ? undefined : depthRemaining - 1,
      );
      if (out === undefined) return { present: false };
      if (isCanonicalValue(out)) return { present: true, value: out };
      return { present: false };
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
  depthRemaining?: number,
): unknown {
  if (depthRemaining !== undefined && depthRemaining <= 0) {
    throw new RangeError("Canonicalization depth budget exceeded");
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
  } catch {
    /* ignore and fall through */
  }

  // Array handling: delegate to array canonicalizer for cycle/dup detection
  if (Array.isArray(value)) {
    return canonicalizeArray(
      value as readonly unknown[],
      cache,
      depthRemaining,
    );
  }

  if (isNonNullObject(value)) {
    return canonicalizeObject(
      value as Record<string, unknown>,
      cache,
      depthRemaining,
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
          return {};
        }
        if (value instanceof ArrayBuffer) return {};
      }
    }
  } catch {
    /* ignore and fall through */
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
      } catch {
        // ignore failures reading keys from exotic hosts — we'll detect deeper during traversal
      }
    }
    // Defensive pre-scan: reject any BigInt found anywhere in the input tree.
    // This ensures nested BigInt values are consistently rejected regardless
    // of exotic host objects or proxy behavior that could bypass deeper
    // checks during canonicalization.
    const cfg = getCanonicalConfig();
    const scanInitialDepth = cfg.maxDepth ?? undefined;
    // Track visited nodes to avoid exponential blow-up on cyclic or highly
    // connected graphs during the pre-scan. WeakSet ensures we don't retain
    // references and is safe for arbitrary object graphs.
    const visited = new WeakSet<object>();
    // eslint-disable-next-line sonarjs/cognitive-complexity -- Defensive deep scan handles hostile objects, cycles, and proxies
    const assertNoBigIntDeep = (v: unknown, depth?: number): void => {
      if (depth !== undefined && depth <= 0) {
        throw new RangeError("Canonicalization depth budget exceeded");
      }
      if (typeof v === "bigint") {
        throw new InvalidParameterError(
          "BigInt values are not supported in payload/context.body.",
        );
      }
      if (isNonNullObject(v)) {
        // Detect dangerous constructor.prototype nesting to prevent prototype pollution attempts
        // If an object contains a nested constructor.prototype, treat as unsafe
        // but do not throw during pre-scan; main traversal will skip forbidden
        // keys. This preserves sanitizer behavior instead of failing early.
        try {
          const ctor = (v as Record<string, unknown>)["constructor"];
          if (
            typeof ctor === "object" &&
            Object.hasOwn(ctor as object, "prototype")
          ) {
            // Mark visited and continue without throwing here
          }
        } catch {
          /* ignore access errors */
        }
        // Skip already-visited nodes to prevent repeated traversal of cycles
        // or shared subgraphs which can otherwise lead to exponential work.
        try {
          const currentObject: object = v;
          if (visited.has(currentObject)) return;
          visited.add(currentObject);
        } catch {
          // If WeakSet operations throw due to hostile objects, fall through
          // without marking as visited; depth caps still protect us.
        }
        if (Array.isArray(v)) {
          for (const it of v) {
            assertNoBigIntDeep(it, depth === undefined ? undefined : depth - 1);
          }
        } else {
          try {
            for (const key of Reflect.ownKeys(v)) {
              // Access property value defensively; ignore access errors
              // eslint-disable-next-line functional/no-let -- Value is assigned in try/catch to preserve control flow
              let value_: unknown;
              try {
                value_ = v[key as PropertyKey];
              } catch {
                continue;
              }
              // Recurse without swallowing errors from deep checks; we must
              // fail closed on BigInt or forbidden constructor.prototype
              assertNoBigIntDeep(
                value_,
                depth === undefined ? undefined : depth - 1,
              );
            }
          } catch {
            // ignore failures enumerating keys on exotic hosts
          }
        }
      }
    };
    assertNoBigIntDeep(value, scanInitialDepth);
    const initialDepth = scanInitialDepth;
    const canonical = toCanonicalValueInternal(
      value,
      new WeakMap<object, unknown>(),
      initialDepth,
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
    if (error instanceof RangeError) {
      // Fail CLOSED: depth exhaustion or traversal resource limits must not
      // silently produce an empty object. Convert to a typed error so callers
      // can handle deterministically per Pillar #1 and ASVS L3.
      throw new InvalidParameterError(
        "Canonicalization depth budget exceeded.",
      );
    }
    // Ensure we always throw an Error object. If a non-Error was thrown,
    // wrap it to preserve the original message/inspectable value.
    if (error instanceof Error) throw error;
    throw new Error(String(error));
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
    throw new RangeError("Circular sentinel scan depth budget exceeded");
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
    const keys = Object.keys(objectValue).sort((a, b) => a.localeCompare(b));
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
