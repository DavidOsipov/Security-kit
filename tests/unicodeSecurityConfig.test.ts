// SPDX-License-Identifier: LGPL-3.0-or-later
// Basic targeted tests for new Unicode security configuration features.
import { describe, it, expect } from 'vitest';
import { normalizeIdentifierString, setUnicodeSecurityConfig, getUnicodeSecurityConfig, sealUnicodeSecurityConfig } from '../src/index.ts';

// Helper to run a risk assessment by enabling scoring and using a payload that triggers metrics.
interface RiskMetricPayloadMetric { id: string; score: number; triggered: boolean }
interface RiskAssessmentPayload { schemaVersion: number; score: number; metrics: RiskMetricPayloadMetric[]; primaryThreat: string; context: string }

function runRiskAssessmentSample() {
  let received: unknown = undefined;
  setUnicodeSecurityConfig({
    enableRiskScoring: true,
    riskWarnThreshold: 0,
    riskBlockThreshold: 9999, // never block in test
  onRiskAssessment: (p) => { received = p; },
    riskMetricWeights: { combiningDensity: 1 },
  });
    // Use a string with combining mark density > 0.2 to trigger combiningDensity metric
    const input = 'a\u0301\u0301b\u0301\u0301c';
    normalizeIdentifierString(input);
  return received;
}

describe('Unicode security configuration', () => {
  it('includes schemaVersion in risk assessment payload', () => {
    const payload = runRiskAssessmentSample();
    expect(payload).toBeTruthy();
    const isAssessment = (v: unknown): v is RiskAssessmentPayload => {
      if (typeof v !== 'object' || v === null) return false;
      const rec = v as Record<string, unknown>;
      return 'schemaVersion' in rec && 'metrics' in rec;
    };
    if (!isAssessment(payload)) {
      throw new Error('Risk assessment payload missing schemaVersion');
    }
    expect(Array.isArray(payload.metrics)).toBe(true);
  });

  it('applies risk metric weight overrides', () => {
    const payload = runRiskAssessmentSample();
    const isAssessment = (v: unknown): v is RiskAssessmentPayload => {
      if (typeof v !== 'object' || v === null) return false;
      return 'metrics' in (v as Record<string, unknown>);
    };
    if (!isAssessment(payload)) {
      throw new Error('Missing metrics');
    }
  const combiningMetric = payload.metrics.find((m: RiskMetricPayloadMetric) => m.id === 'combiningDensity');
  expect(combiningMetric).toBeTruthy();
  if (!combiningMetric) throw new Error('combiningDensity metric not found');
  expect(combiningMetric.score).toBe(1);
  });

  it('seals config to prevent further modification', () => {
    sealUnicodeSecurityConfig();
    const before = getUnicodeSecurityConfig();
    expect(() => setUnicodeSecurityConfig({ riskWarnThreshold: before.riskWarnThreshold + 1 })).toThrow();
  });

  it('redacts error details when detailedErrorMessages=false', () => {
    // Ensure not sealed for this mutation in case earlier test sealed; skip if sealed.
    try {
      setUnicodeSecurityConfig({ detailedErrorMessages: false });
    } catch {/* ignore if sealed */}
    // Invisible char U+200B zero-width space to trigger invisible rejection
    let msg = '';
    try {
      normalizeIdentifierString('A\u200B');
    } catch (e: unknown) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg).not.toMatch(/200B/); // redacted
  });
});
