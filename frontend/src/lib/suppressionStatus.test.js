import { describe, it, expect } from 'vitest'
import { isExpired, isExpiringSoon, suppressionStatus } from './suppressionStatus'

const NOW = new Date('2026-07-08T00:00:00Z').getTime()
const daysFromNow = (d) => new Date(NOW + d * 86_400_000).toISOString()

describe('suppressionStatus', () => {
  it('treats a suppression with no expiry as active (never expired/soon)', () => {
    const s = { expires_at: null }
    expect(isExpired(s, NOW)).toBe(false)
    expect(isExpiringSoon(s, NOW)).toBe(false)
    expect(suppressionStatus(s, NOW)).toBe('active')
  })

  it('flags a past expiry as expired', () => {
    const s = { expires_at: daysFromNow(-1) }
    expect(isExpired(s, NOW)).toBe(true)
    expect(isExpiringSoon(s, NOW)).toBe(false)
    expect(suppressionStatus(s, NOW)).toBe('expired')
  })

  it('flags an expiry within 7 days as expiring soon', () => {
    const s = { expires_at: daysFromNow(3) }
    expect(isExpired(s, NOW)).toBe(false)
    expect(isExpiringSoon(s, NOW)).toBe(true)
    expect(suppressionStatus(s, NOW)).toBe('soon')
  })

  it('an expiry beyond 7 days is active, not soon', () => {
    const s = { expires_at: daysFromNow(30) }
    expect(isExpiringSoon(s, NOW)).toBe(false)
    expect(suppressionStatus(s, NOW)).toBe('active')
  })

  it('the 7-day boundary is inclusive of exactly 7 days and excludes now', () => {
    expect(isExpiringSoon({ expires_at: daysFromNow(7) }, NOW)).toBe(true)
    // exactly now → not "soon" (ms must be > 0) and not expired (must be < now)
    const atNow = { expires_at: new Date(NOW).toISOString() }
    expect(isExpiringSoon(atNow, NOW)).toBe(false)
    expect(isExpired(atNow, NOW)).toBe(false)
  })
})
