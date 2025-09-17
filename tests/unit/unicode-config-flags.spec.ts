import { describe, it, expect, beforeEach } from 'vitest';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig } from '../../src/config.ts';
import { normalizeInputString } from '../../src/canonical.ts';
import { InvalidParameterError, SecurityValidationError } from '../../src/errors.ts';

// NOTE: These tests run in a non-production environment by default. They verify
// that disabling certain rejection flags allows inputs that would otherwise be rejected
// while leaving Bidi rejection protected unless explicitly disabled.

const BIDI_SAMPLE = '\u202Eabc'; // RLO followed by text
const INVISIBLE_SAMPLE = 'a\u200B b'; // zero-width space
const DANGEROUS_SAMPLE = 'a\u0001b';

describe('Unicode security config flags', () => {
  beforeEach(() => {
    // reset to defaults (non-production baseline) by setting without overrides
    setUnicodeSecurityConfig({
      rejectBidiControls: true,
      rejectInvisibleChars: true,
      rejectDangerousRanges: true,
      rejectIntroducedStructuralChars: true,
      requireUnicodeDataIntegrity: false,
    });
  });

  it('rejects bidi by default', () => {
    expect(() => normalizeInputString(BIDI_SAMPLE, 'bidi')).toThrow(InvalidParameterError);
  });

  it('allows disabling bidi in non-production', () => {
    setUnicodeSecurityConfig({ rejectBidiControls: false });
    expect(() => normalizeInputString(BIDI_SAMPLE, 'bidi-disabled')).not.toThrow();
  });

  it('rejects invisible by default and allows disabling', () => {
    expect(() => normalizeInputString(INVISIBLE_SAMPLE, 'inv')).toThrow(InvalidParameterError);
    setUnicodeSecurityConfig({ rejectInvisibleChars: false });
    expect(() => normalizeInputString(INVISIBLE_SAMPLE, 'inv-disabled')).not.toThrow();
  });

  it('rejects dangerous range by default and allows disabling', () => {
    expect(() => normalizeInputString(DANGEROUS_SAMPLE, 'danger')).toThrow(InvalidParameterError);
    setUnicodeSecurityConfig({ rejectDangerousRanges: false });
    expect(() => normalizeInputString(DANGEROUS_SAMPLE, 'danger-disabled')).not.toThrow();
  });

  it('structural introduction rejection can be disabled (soft path)', () => {
    // Introduce structural char via normalization: fullwidth slash to regular slash
    const INPUT = '\uFF0Fa';
    expect(() => normalizeInputString(INPUT, 'struct-enabled')).toThrow(InvalidParameterError);
    setUnicodeSecurityConfig({ rejectIntroducedStructuralChars: false });
    expect(() => normalizeInputString(INPUT, 'struct-disabled')).not.toThrow();
  });
});

describe('Unicode integrity requirement scaffold', () => {
  it('throws SecurityValidationError when integrity required and header invalid (simulated)', () => {
    // Force integrity requirement
    setUnicodeSecurityConfig({ requireUnicodeDataIntegrity: true });
    // Simulate calling loader indirectly is complex; instead we directly invoke placeholder integrity
    // by importing and calling with bad bytes. This keeps unit test lightweight.
    // Import dynamically to avoid circular reference if any.
    const { verifyUnicodeDataIntegrity } = require('../../src/unicodeIntegrity.ts');
    const bad = new Uint8Array([0,1,2,3,4]);
    expect(() => verifyUnicodeDataIntegrity('identifier', 'standard', bad)).toThrow(SecurityValidationError);
  });
});
