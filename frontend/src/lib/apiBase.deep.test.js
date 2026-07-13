import { describe, it, expect, beforeEach } from 'vitest';
import { apiUrl, getApiBase, authHeaders, formatHttpApiError, setStoredAccessToken, clearStoredAccessToken } from './apiBase.js';

describe('apiBase deep', () => {
  beforeEach(() => clearStoredAccessToken())

  it('getApiBase default', () => {
    expect(typeof getApiBase()).toBe('string')
  })

  it('authHeaders bearer', () => {
    setStoredAccessToken('abc')
    expect(authHeaders().Authorization).toBe('Bearer abc')
  })

  it('formatHttpApiError 404', () => {
    expect(formatHttpApiError({ status: 404 }, '')).toMatch(/404|not found/i)
  })

  it('formatHttpApiError payment required', () => {
    expect(formatHttpApiError({ status: 402 }, 'upgrade')).toContain('upgrade')
  })

  it('apiUrl relative path', () => {
    expect(apiUrl('/api/health')).toMatch(/\/api\/health$/)
  })
})
