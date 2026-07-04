import { describe, it, expect, beforeEach } from 'vitest'
import { getStoredAccessToken, setStoredAccessToken, clearStoredAccessToken } from './apiBase.js'
describe('apiBase tokens', () => {
  beforeEach(() => clearStoredAccessToken())
  it('round trip', () => {
    setStoredAccessToken('tok')
    expect(getStoredAccessToken()).toBe('tok')
    clearStoredAccessToken()
    expect(getStoredAccessToken()).toBeNull()
  })
})