import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { normalizeInputString } from '../src/canonical.ts';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../src/config.ts';
import { SecurityValidationError } from '../src/errors.ts';

// These tests exercise the new optional Unicode cumulative risk scoring scaffold.
// They deliberately lower thresholds to force deterministic behavior with short inputs,
// avoiding resource heavy strings while still validating scoring paths.

describe('unicode risk scoring (optional defense-in-depth)', () => {
  const original = getUnicodeSecurityConfig();

  afterAll(() => {
    // Restore original configuration to avoid test order dependence.
    setUnicodeSecurityConfig({
      enableRiskScoring: original.enableRiskScoring,
      riskWarnThreshold: original.riskWarnThreshold,
      riskBlockThreshold: original.riskBlockThreshold,
      onRiskAssessment: original.onRiskAssessment,
    });
  });

  it('does not invoke risk assessment hook for pure ASCII fast-path input', () => {
    let called = false;
    setUnicodeSecurityConfig({
      enableRiskScoring: true,
      riskWarnThreshold: 10,
      riskBlockThreshold: 50,
      onRiskAssessment: () => { called = true; },
    });
    const out = normalizeInputString('hello');
    expect(out).toBe('hello');
    expect(called).toBe(false); // fast path should bypass scoring
  });

  it('invokes risk assessment hook for non-ASCII input and does not block when under threshold', () => {
    let observedScore: number | undefined;
    setUnicodeSecurityConfig({
      enableRiskScoring: true,
      riskWarnThreshold: 10,
      riskBlockThreshold: 100, // set very high so we do not block
      onRiskAssessment: (d) => { observedScore = d.score; },
    });
    // Use a ligature + greek letter to trigger expansion + mixed script signals
    const input = 'ﬀο';
    const out = normalizeInputString(input);
    expect(out.length).toBeGreaterThan(0);
    expect(observedScore).toBeTypeOf('number');
    expect((observedScore ?? 0)).toBeGreaterThanOrEqual(0);
  });

  it('throws SecurityValidationError when cumulative score exceeds block threshold', () => {
    setUnicodeSecurityConfig({
      enableRiskScoring: true,
      // Low thresholds to force block: the constructed string should score > 30 (expansion + mixed script + low entropy)
      riskWarnThreshold: 10,
      riskBlockThreshold: 30,
      onRiskAssessment: undefined,
    });
    // Construct a string that triggers multiple soft signals without hard-fail earlier:
    // - Several ligatures (ﬀ) to create expansion ratio (~2x)
    // - Greek letter for mixed script
    // - Repetition for low entropy
    const risky = 'ﬀ'.repeat(5) + 'ο' + 'ﬀ'.repeat(5);
    expect(() => normalizeInputString(risky)).toThrow(SecurityValidationError);
  });
});
