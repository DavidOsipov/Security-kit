import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createSecureURL, encodeHostLabel } from '../../src/url'
import { setUrlHardeningConfig, getUrlHardeningConfig } from '../../src/config'

describe('url.ts IDNA and authority edge cases', () => {
  let saved = getUrlHardeningConfig()
  beforeEach(() => { saved = getUrlHardeningConfig() })
  afterEach(() => { setUrlHardeningConfig(saved) })

  it('rejects enabling IDNA Option B without provider', () => {
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true })).toThrow()
  })

  it('rejects provider that returns non-ASCII at configuration time', () => {
    const provider = { toASCII: (_s: string) => 'tést' }
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider as any })).toThrow()
  })

  it('rejects provider that returns control characters at configuration time', () => {
    const provider = { toASCII: (_s: string) => '\u0000' }
    expect(() => setUrlHardeningConfig({ enableIdnaToAscii: true, idnaProvider: provider as any })).toThrow()
  })

  it('encodeHostLabel throws when IDNA provider missing toASCII', () => {
    // Ensure that using encodeHostLabel without a proper provider throws
    setUrlHardeningConfig({ enableIdnaToAscii: false })
    expect(() => encodeHostLabel('tést')).toThrow()
  })

  it('rejects raw non-ASCII authority by default', () => {
    expect(() => createSecureURL('https://tést.example.com')).toThrow()
  })

  it('rejects hostname containing bidi control characters', () => {
    // RLO (U+202E) should be rejected in hostnames
    expect(() => createSecureURL('https://exa\u202Emple.com')).toThrow()
  })

  it('rejects empty label/pre-IDNA invalid hostnames', () => {
    // leading dot creates an empty label
    expect(() => createSecureURL('https://.example.com')).toThrow()
  })
})
