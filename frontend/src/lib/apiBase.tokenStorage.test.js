import { describe, it, expect, beforeEach } from 'vitest'
import {
  getStoredAccessToken,
  setStoredAccessToken,
  clearStoredAccessToken,
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
