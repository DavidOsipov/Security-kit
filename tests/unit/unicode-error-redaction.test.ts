import { describe, it, expect } from 'vitest';
import { makeUnicodeError, UnicodeErrorCode } from '../../src/errors.ts';
import { setUnicodeSecurityConfig, getUnicodeSecurityConfig, normalizeIdentifierString } from '../../src/index.ts';

// Helper to toggle detailedErrorMessages safely then restore.
function withDetailFlag(flag: boolean, fn: () => void) {
  const before = getUnicodeSecurityConfig();
  setUnicodeSecurityConfig({ detailedErrorMessages: flag });
  try { fn(); } finally { setUnicodeSecurityConfig({ detailedErrorMessages: before.detailedErrorMessages }); }
}

describe('makeUnicodeError redaction', () => {
  it('emits full detail when detailedErrorMessages=true', () => {
    withDetailFlag(true, () => {
      const err = makeUnicodeError('ctx', UnicodeErrorCode.Bidi, 'Contains bidirectional control characters (\u202E) — rejected.');
      expect(err.message).toContain('(\u202E)');
      expect(err.message).toContain('[code=ERR_UNICODE_BIDI]');
    });
  });
  it('redacts detail when detailedErrorMessages=false', () => {
    withDetailFlag(false, () => {
      const err = makeUnicodeError('ctx', UnicodeErrorCode.Bidi, 'Contains bidirectional control characters (\u202E) — rejected.');
      expect(err.message).not.toContain('\u202E');
      expect(err.message).toMatch(/Rejected for security policy/);
    });
  });
});

describe('normalizeIdentifierString integration redaction', () => {
  it('redacts offending characters in thrown error when config disables detail', () => {
    withDetailFlag(false, () => {
      try {
        normalizeIdentifierString('\u202Etest', 'test');
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg).toContain('[code=ERR_UNICODE_BIDI]');
        expect(msg).toMatch(/Rejected for security policy/);
        expect(msg).not.toContain('\u202E');
      }
    });
  });
});
