import { describe, it, expect } from 'vitest'
import { _redact, sanitizeLogMessage } from '../../src/utils'

describe('sanitizer representation variants', () => {
  it('typed arrays are represented opaquely or as safe metadata (no raw byte leak)', () => {
    const secret = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    // Use the exported _redact which runs the normalization pass and redaction.
    const normalized = _redact(secret)
    // The sanitizer may return a string token or an object with __typedArray metadata.
    if (typeof normalized === 'string') {
      expect(normalized).toMatch(/\[TypedArray\]/)
    } else {
      const json = JSON.stringify(normalized)
      // Must not include raw hex or decimal byte sequences from the original buffer
      expect(json).not.toContain('deadbeef')
      expect(json).toMatch(/__typedArray|byteLength/)
    }
  })

  it('Sets are represented opaquely or as safe metadata (no entries expanded)', () => {
    const s = new Set([1, 2, 3])
    const normalized = _redact(s)
    if (typeof normalized === 'string') {
      expect(normalized).toMatch(/\[Array\]|\[Set/)
    } else {
      const json = JSON.stringify(normalized)
      // Should not expand entries into an array of values
      expect(json).not.toContain('[1,')
      // Should expose metadata for Set
      expect(json).toMatch(/__type|Set|size|content-not-logged/)
    }
  })
})
