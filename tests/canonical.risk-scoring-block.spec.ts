import { describe, it, expect } from 'vitest';
import { normalizeInputString } from '../src/canonical.ts';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../src/config.ts';
import { SecurityValidationError } from '../src/errors.ts';

// This test ensures that when risk scoring is enabled with very low thresholds,
// a string triggering multiple soft metrics will cause a SecurityValidationError.
// We deliberately craft an input with: combining marks (density/run) + low entropy +
// homoglyph suspects (mixed script) + potential expansion.

describe('unicode risk scoring blocking', () => {
  it('blocks when cumulative score >= block threshold', () => {
    const original = getUnicodeSecurityConfig();
    try {
      setUnicodeSecurityConfig({
        enableRiskScoring: true,
        riskWarnThreshold: 10,
        riskBlockThreshold: 20,
      });
  // Craft risky string that *passes* hard validation but triggers multiple soft metrics:
  // - mixedScriptHomoglyph: include Cyrillic A (\u0410) amid ASCII letters
  // - lowEntropy: dominated by a small alphabet
  // - combiningRun / combiningDensity (soft range): use 4 combining marks (< hard cap 5)
  // - expansionSoft: add some characters that slightly expand after normalization (use compatibility forms)
  const base = 'a'.repeat(50);
  const homoglyph = '\u0410'; // Cyrillic capital A
  const combining = '\u0301'.repeat(4); // 4 combining acute accents (below hard fail >5)
  const compat = '\u2160'; // Roman numeral I (NFKC -> 'I') causing mild expansion influence
  const risky = base + homoglyph + combining + compat + 'bbb'.repeat(5);
  expect(() => normalizeInputString(risky, 'risk-test')).toThrow(SecurityValidationError);
    } finally {
      // Restore to avoid side-effects for other tests
      setUnicodeSecurityConfig({
        enableRiskScoring: original.enableRiskScoring,
        riskWarnThreshold: original.riskWarnThreshold,
        riskBlockThreshold: original.riskBlockThreshold,
      });
    }
  });
});
