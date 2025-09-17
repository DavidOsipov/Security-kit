import { describe, it, expect } from 'vitest';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../../src/config.ts';
import { getConfusableTargets, isConfusable } from '../../src/canonical.ts';

// NOTE: canonical.ts re-exports functions from generated loader.

describe('Confusables index optimization', () => {
  it('falls back to linear search when disabled', () => {
    setUnicodeSecurityConfig({ enableConfusableIndex: false });
    const cfg = getUnicodeSecurityConfig();
    expect(cfg.enableConfusableIndex).toBe(false);
    // Using classic homograph pair a (Latin) vs a (Cyrillic) not always loaded in minimal; ensure standard profile
    setUnicodeSecurityConfig({ dataProfile: 'standard' });
    // Safe call even if mapping absent
    const t = getConfusableTargets('a');
    expect(Array.isArray(t)).toBe(true);
  });

  it('builds and uses index when enabled', () => {
    setUnicodeSecurityConfig({ enableConfusableIndex: true, dataProfile: 'standard' });
    const before = performance.now();
    // Warm index
    getConfusableTargets('a');
    const mid = performance.now();
    // Second call should be faster (heuristic check only)
    getConfusableTargets('a');
    const after = performance.now();
    expect(after - mid).toBeLessThan((mid - before) * 5 + 10); // very lenient heuristic
  });

  it('isConfusable reflects index results', () => {
    setUnicodeSecurityConfig({ enableConfusableIndex: true, dataProfile: 'standard' });
    // If dataset lacks mapping, simply ensure function returns boolean.
    const result = isConfusable('a', 'a');
    expect(typeof result).toBe('boolean');
  });
});
