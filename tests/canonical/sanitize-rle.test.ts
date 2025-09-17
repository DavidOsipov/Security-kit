// SPDX-License-Identifier: LGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { sanitizeForLogging } from '../../src/index.ts';

// Tests to ensure run-length encoding collapse of control markers works and prevents amplification.

describe('sanitizeForLogging RLE collapse', () => {
  it('collapses long runs of [CTRL]', () => {
    const ctrlChar = String.fromCharCode(1); // will map to [CTRL]
    const input = ctrlChar.repeat(40);
    const out = sanitizeForLogging(input, 500);
    // Expect pattern like [CTRL]xN after collapse
    expect(/\[CTRL]x\d+/.test(out)).toBe(true);
  });

  it('collapses mixed interleaved control/BIDI markers', () => {
    const bidi = '\u202E';
    const ctrl = String.fromCharCode(2);
    const mixed = (bidi + ctrl).repeat(25); // 50 markers
    const out = sanitizeForLogging(mixed, 500);
    // Should not produce 50 explicit markers; length bound check heuristic
    const markerCount = (out.match(/\[CTRL]|\[BIDI]/g) || []).length;
    expect(markerCount).toBeLessThan(20);
  });
});
