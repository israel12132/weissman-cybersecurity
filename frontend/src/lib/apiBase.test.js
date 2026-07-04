import { describe, it, expect } from 'vitest'
import { apiUrl, formatHttpApiError } from './apiBase.js'
describe('apiBase', () => {
  it('apiUrl path', () => expect(apiUrl('/api/health')).toMatch(/\/api\/health$/))
  it('formatHttpApiError', () => {
    expect(formatHttpApiError({ status: 503, statusText: 'Unavailable' }, 'busy')).toContain('busy')
  })
})