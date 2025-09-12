import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createSecureURL, validateURL, strictDecodeURIComponentOrThrow } from '../../src/url'
import { setUrlHardeningConfig, getUrlHardeningConfig } from '../../src/config'

describe('url.ts batch2 targets', () => {
  let saved: ReturnType<typeof getUrlHardeningConfig>
  beforeEach(() => { saved = getUrlHardeningConfig() })
  afterEach(() => { setUrlHardeningConfig(saved) })

  it('rejects malformed percent-encoding in query when toggle enabled', () => {
    setUrlHardeningConfig({ validatePathPercentEncoding: true })
    // malformed percent in query value
    expect(() => createSecureURL('https://example.com', [], { a: '%G1' })).toThrow()
  })

  it('rejects double-encoded traversal in path segments', () => {
    // craft a segment that decodes into navigation
    expect(() => createSecureURL('https://example.com', ['..%2e'])).toThrow()
  })

  it('enforces maxLength on opaque builders tail cases', () => {
    // generate a long mailto address
    const long = 'mailto:' + 'a'.repeat(3000) + '@example.com'
    expect(() => createSecureURL(long)).toThrow()
  })

  it('strictDecodeURIComponentOrThrow throws on control characters after decode', () => {
    expect(() => strictDecodeURIComponentOrThrow('%00')).toThrow()
  })
})
