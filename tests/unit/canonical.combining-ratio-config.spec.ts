import { describe, it, expect } from 'vitest';
import { normalizeInputString, setUnicodeSecurityConfig } from '../../src/canonical';
import { InvalidParameterError } from '../../src/errors';

// Construct strings with controlled combining mark ratios.
function buildString(baseChar: string, combining: string, baseCount: number, combiningPerBase: number) {
  let out = '';
  for (let i = 0; i < baseCount; i++) {
    out += baseChar + combining.repeat(combiningPerBase);
  }
  return out;
}

describe('Combining ratio configuration', () => {
  it('rejects when ratio above lowered threshold', () => {
    setUnicodeSecurityConfig({ maxCombiningRatio: 0.05, minCombiningRatioScanLength: 10 });
    // baseCount=20, combiningPerBase=1 => total chars = 40, combining=20 -> ratio=0.5 > 0.05
    const s = buildString('a', '\u0301', 20, 1);
    expect(() => normalizeInputString(s, 'combining-low-threshold')).toThrow(InvalidParameterError);
  });

  it('allows when below threshold and length below scan minimum', () => {
    setUnicodeSecurityConfig({ maxCombiningRatio: 0.1, minCombiningRatioScanLength: 100 });
    // length < minCombiningRatioScanLength so ratio check not applied
    const s = buildString('b', '\u0301', 10, 1); // ratio 0.5 but total length 20 < 100 => allowed
    expect(() => normalizeInputString(s, 'combining-below-scan-min')).not.toThrow();
  });

  it('allows benign ratio within threshold', () => {
    setUnicodeSecurityConfig({ maxCombiningRatio: 0.6, minCombiningRatioScanLength: 10 });
    const s = buildString('c', '\u0301', 5, 1); // ratio 0.5 <= 0.6
    expect(() => normalizeInputString(s, 'combining-benign')).not.toThrow();
  });
});
