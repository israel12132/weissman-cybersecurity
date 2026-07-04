import { describe, it, expect } from 'vitest'
import { formatHttpApiError } from './apiBase.js'
describe('formatHttpApiError', () => {
  it('404 helpful', () => {
    expect(formatHttpApiError({ status: 404 }, '')).toMatch(/404/)
  })
  it('503 detail', () => {
    expect(formatHttpApiError({ status: 503, statusText: 'Unavailable' }, 'busy')).toContain('busy')
  })
})