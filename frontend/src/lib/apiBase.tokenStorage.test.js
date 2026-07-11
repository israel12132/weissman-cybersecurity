import { describe, it, expect, beforeEach } from 'vitest'
import {
  getStoredAccessToken,
  setStoredAccessToken,
  clearStoredAccessToken,
  isSameApiOrigin,
} from './apiBase.js'

const ACCESS_TOKEN_KEY = 'weissman_access_token'

describe('apiBase token storage hardening', () => {
  beforeEach(() => {
    clearStoredAccessToken()
    if (typeof localStorage !== 'undefined') localStorage.clear()
    if (typeof sessionStorage !== 'undefined') sessionStorage.clear()
  })

  it('never writes the token to localStorage', () => {
    setStoredAccessToken('secret-token')
    expect(getStoredAccessToken()).toBe('secret-token')
    expect(localStorage.getItem(ACCESS_TOKEN_KEY)).toBeNull()
  })

  it('purges a token left behind in localStorage by an older build', () => {
    localStorage.setItem(ACCESS_TOKEN_KEY, 'legacy-token')
    // Any accessor touching the store must scrub the legacy value.
    getStoredAccessToken()
    expect(localStorage.getItem(ACCESS_TOKEN_KEY)).toBeNull()
  })

  it('does not resurrect a session from a localStorage token', () => {
    localStorage.setItem(ACCESS_TOKEN_KEY, 'legacy-token')
    expect(getStoredAccessToken()).toBeNull()
  })

  it('clears the token from memory and sessionStorage on logout', () => {
    setStoredAccessToken('secret-token')
    clearStoredAccessToken()
    expect(getStoredAccessToken()).toBeNull()
    expect(sessionStorage.getItem(ACCESS_TOKEN_KEY)).toBeNull()
    expect(localStorage.getItem(ACCESS_TOKEN_KEY)).toBeNull()
  })
})

describe('isSameApiOrigin — bearer token is never leaked cross-origin', () => {
  it('allows relative paths (resolve to same/API origin)', () => {
    expect(isSameApiOrigin('/api/findings')).toBe(true)
  })
  it('allows the current same-origin absolute URL', () => {
    expect(isSameApiOrigin(`${window.location.origin}/api/x`)).toBe(true)
  })
  it('rejects a foreign origin', () => {
    expect(isSameApiOrigin('https://evil.example.com/steal')).toBe(false)
  })
  it('rejects a malformed URL rather than defaulting to allow', () => {
    expect(isSameApiOrigin('http://[::bad')).toBe(false)
  })
})
