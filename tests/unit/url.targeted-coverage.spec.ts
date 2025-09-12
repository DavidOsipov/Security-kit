import { describe, it, expect } from 'vitest'
import {
  createSecureURL,
  validateURL,
  strictDecodeURIComponentOrThrow,
  encodeHostLabel,
} from '../../src/url'

describe('url.ts targeted coverage', () => {
  it('rejects malformed authority with extra bracket', () => {
    expect(() => createSecureURL({ base: 'https://[::1]]:80' })).toThrow()
  })

  it('encodeHostLabel throws when IDNA provider missing or invalid', () => {
    // @ts-ignore - simulate bad provider
    expect(() => encodeHostLabel('пример', null as any)).toThrow()
    // provider that throws
    const badProvider = { toASCII: () => { throw new Error('boom') } }
    expect(() => encodeHostLabel('пример', badProvider as any)).toThrow()
  })

  it('strictDecodeURIComponentOrThrow throws on malformed percent sequences', () => {
    expect(() => strictDecodeURIComponentOrThrow('%E0%A4')).toThrow()
    expect(() => strictDecodeURIComponentOrThrow('%ZZ')).toThrow()
  })

  it('validateURL enforces scheme and maxLength tail checks', () => {
    const r1 = validateURL({ url: 'javascript:alert(1)' })
    expect(r1.ok).toBe(false)

    const long = 'https://' + 'a'.repeat(5000) + '.com'
    const r2 = validateURL({ url: long })
    expect(r2.ok).toBe(false)
  })

  it('rejects IPv4 octet out of range during validation', () => {
    const r = validateURL({ url: 'http://256.1.1.1/' })
    expect(r.ok).toBe(false)
  })
})
