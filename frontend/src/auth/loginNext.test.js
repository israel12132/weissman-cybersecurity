import { describe, it, expect } from 'vitest'
import {
  sanitizeNextPath,
  commandCenterHomeForRole,
  resolvePostLoginHref,
  normalizeMfaCode,
  flagshipLoginHref,
} from './loginNext.js'

describe('sanitizeNextPath', () => {
  it('accepts Command Center paths', () => {
    expect(sanitizeNextPath('/command-center/findings')).toBe('/command-center/findings')
  })
  it('prefixes CC-relative paths', () => {
    expect(sanitizeNextPath('/operations')).toBe('/command-center/operations')
  })
  it('rejects open redirects', () => {
    expect(sanitizeNextPath('https://evil.example/')).toBeNull()
    expect(sanitizeNextPath('//evil.example')).toBeNull()
    expect(sanitizeNextPath('/api/login')).toBeNull()
    expect(sanitizeNextPath('/login')).toBeNull()
  })
  it('decodes query values', () => {
    expect(sanitizeNextPath('%2Fcommand-center%2Fjobs')).toBe('/command-center/jobs')
  })
})

describe('resolvePostLoginHref', () => {
  it('uses role home when next is missing', () => {
    expect(commandCenterHomeForRole({ role: 'ceo' })).toBe('/command-center/')
    expect(commandCenterHomeForRole({ role: 'operator' })).toBe('/command-center/operations')
    expect(resolvePostLoginHref({ role: 'analyst' }, '')).toBe('/command-center/operations')
  })
  it('prefers a safe next', () => {
    expect(resolvePostLoginHref({ role: 'ceo' }, '/command-center/engines')).toBe(
      '/command-center/engines',
    )
  })
})

describe('normalizeMfaCode', () => {
  it('keeps six digits from paste', () => {
    expect(normalizeMfaCode('12 34-56abc')).toBe('123456')
  })
})

describe('flagshipLoginHref', () => {
  it('omits next for the cockpit home', () => {
    expect(flagshipLoginHref('/')).toBe('/login')
  })
  it('encodes a deep CC path', () => {
    expect(flagshipLoginHref('/findings')).toBe(
      '/login?next=%2Fcommand-center%2Ffindings',
    )
  })
})
