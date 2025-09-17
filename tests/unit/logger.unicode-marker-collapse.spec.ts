import { describe, it, expect } from 'vitest';
import { sanitizeForLogging } from '../../src/canonical.ts';

// We craft inputs that will produce BIDI and control markers after sanitization.
// BIDI: \u202E (RIGHT-TO-LEFT OVERRIDE)
// Control: \u0001 (START OF HEADING)

describe('sanitizeForLogging marker collapsing', () => {
  it('collapses long homogeneous control marker runs', () => {
    const raw = '\u0001'.repeat(20);
    const out = sanitizeForLogging(raw, 500);
    expect(out).toMatch(/\[CTRL]x\d+/);
  });

  it('collapses heterogeneous mixed runs into combined token', () => {
    // Alternate bidi/control to try to evade repetition cap
    const pattern = '\u202E\u0001'.repeat(12); // 24 markers
    const out = sanitizeForLogging(pattern, 500);
    // Expect combined aggregation token
    expect(out).toMatch(/\[CTRL\|BIDI]x\d+/);
  });
});
