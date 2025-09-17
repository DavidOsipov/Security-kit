// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
// Import regex & internal exported list via canonical.ts test export
import { __test_structuralRiskChars } from '../../src/canonical.ts';
import { STRUCTURAL_RISK_CHARS } from '../../src/config.ts';

describe('STRUCTURAL_RISK_CHARS parity', () => {
  it('character list matches regex character class set', () => {
    const pattern = STRUCTURAL_RISK_CHARS.source;
    // Extract inside of [...] by simple heuristic (pattern already curated)
    const classMatch = pattern.match(/^\[(.*)\]$/);
    expect(classMatch).not.toBeNull();
    const cls = classMatch ? classMatch[1] : '';
    // Remove escape backslashes for single-char tokens
    const fromRegex = new Set(cls.replace(/\\/g, '').split(''));
    for (const ch of __test_structuralRiskChars) {
      expect(fromRegex.has(ch)).toBe(true);
    }
  });
});
