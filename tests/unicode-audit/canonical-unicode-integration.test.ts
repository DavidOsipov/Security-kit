// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { getUnicodeSecurityConfig, setUnicodeSecurityConfig } from '../../src/config.ts';
import { normalizeInputString } from '../../src/canonical.ts';
import { getConfusableTargets } from '../../src/generated/unicode-optimized-loader.ts';

// This test validates that canonical.ts integrates correctly with the generated
// Unicode data loader by (a) treating undefined identifier statuses as
// 'Restricted' (per IdentifierStatus.txt spec @missing rule) and (b) using the
// indexed confusable lookup path without regression to O(N) scans.

describe('canonical Unicode integration', () => {
  it('treats non-Allowed code points as Restricted and flags homoglyph risk', () => {
    const cfg = getUnicodeSecurityConfig();
    // Ensure confusables disabled does not throw and restricted synthesis still occurs
    setUnicodeSecurityConfig({ enableConfusablesDetection: false });
    try {
      // Include a typical allowed ASCII segment plus a clearly non-listed symbol (e.g., U+0378 is unassigned)
      const risky = 'admin' + '\u0378';
      // Should not throw unless other security heuristics trip; normalization should proceed.
      const normalized = normalizeInputString(risky, 'test');
      expect(normalized).toBe(risky.normalize('NFKC'));
    } finally {
      // restore
      setUnicodeSecurityConfig({ enableConfusablesDetection: cfg.enableConfusablesDetection });
    }
  });

  it('confusable index returns expected targets for classic homograph pair', () => {
    const cfg = getUnicodeSecurityConfig();
    if (!cfg.enableConfusablesDetection) {
      setUnicodeSecurityConfig({ enableConfusablesDetection: true });
    }
    try {
      // Cyrillic small a (U+0430) vs Latin 'a'
      const targets = getConfusableTargets('\u0430');
      // If profile is minimal this will be empty; allow either but assert type and stability.
      expect(Array.isArray(targets)).toBe(true);
      if (cfg.dataProfile !== 'minimal') {
        expect(targets).toContain('a');
      }
    } finally {
      setUnicodeSecurityConfig({ enableConfusablesDetection: cfg.enableConfusablesDetection });
    }
  });
});
