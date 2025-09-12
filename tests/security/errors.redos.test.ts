// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { getStackFingerprint } from '../../src/errors';

function buildAdversarialStack(repeat: number): string {
  // Craft lines that previously could stress the regex engine: many parentheses and colons
  const noisySegment = '('.repeat(50) + 'a'.repeat(200) + ':'.repeat(10) + ')'.repeat(50);
  const fileLoc = `(some/path/file.js:123:45)`;
  return Array.from({ length: repeat }, (_, i) => `Error: boom\n    at fn${i} ${fileLoc} ${noisySegment}`).join('\n');
}

describe('getStackFingerprint ReDoS hardening', () => {
  it('produces a stable 8 hex char hash for a normal stack', () => {
    const stack = 'Error: test\n    at fn (file.js:1:2)';
    const fp = getStackFingerprint(stack);
    expect(fp).toMatch(/^[0-9a-f]{8}$/);
  });

  it('handles adversarial large stack without timing out', () => {
    const stack = buildAdversarialStack(40);
    const start = Date.now();
    const fp = getStackFingerprint(stack);
    const elapsed = Date.now() - start;
    expect(fp).toMatch(/^[0-9a-f]{8}$/);
    // Should complete well under 100ms in typical environments; allow generous upper bound
    expect(elapsed).toBeLessThan(500);
  });

  it('is deterministic for identical normalized stacks', () => {
    const s1 = 'Error: X\n    at a (p.js:10:20)';
    const s2 = 'Error: X\n    at a (p.js:10:20)';
    expect(getStackFingerprint(s1)).toBe(getStackFingerprint(s2));
  });

  it('changes when non-file segment differs', () => {
    // Difference placed in function name, not inside the parenthesized file:line:col segment
    const a = 'Error: X\n    at fnA (p.js:10:20)';
    const b = 'Error: X\n    at fnB (p.js:10:20)';
    expect(getStackFingerprint(a)).not.toBe(getStackFingerprint(b));
  });
});
