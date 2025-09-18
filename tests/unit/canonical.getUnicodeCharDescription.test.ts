import { describe, it, expect } from 'vitest';
import { getUnicodeCharDescription } from '../../src/canonical';

describe('getUnicodeCharDescription', () => {
  it('returns known descriptions for mapped code points', () => {
    // Use a few entries that should exist in the UNICODE_CHAR_DESCRIPTIONS map
    // Example: FULLWIDTH LATIN SMALL LETTER A (U+FF41) is in the map
    expect(getUnicodeCharDescription(0xff41)).toContain('FULLWIDTH LATIN SMALL LETTER A');

    // Enclosed alphanumeric example (U+24B6)
  // The implementation returns a human-readable name like "CIRCLED LATIN CAPITAL LETTER A (enclosed character - medium risk)".
  // Check for the substring 'enclosed' case-insensitively to be robust against phrasing differences.
  expect(getUnicodeCharDescription(0x24b6).toLowerCase()).toContain('enclosed');
  });

  it('detects BIDI control characters via range mapping', () => {
    // U+202E (RIGHT-TO-LEFT OVERRIDE) should be classified as BIDI control
  const desc = getUnicodeCharDescription(0x202e);
  // Implementation describes this as a right-to-left control and includes 'right-to-left' wording.
  expect(desc.toLowerCase()).toContain('right-to-left');
  });

  it('falls back to formatted code point for unknown characters', () => {
    // Pick an unlikely code point not in the map or ranges (private-use and common ranges excluded): U+2F800
    const fallback = getUnicodeCharDescription(0x2f800);
    expect(fallback).toMatch(/^Unicode character U\+[0-9A-F]{4,6}$/);
  });
});
