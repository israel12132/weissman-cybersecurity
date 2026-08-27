import { describe, it, expect } from 'vitest'
import { isJobStuck, formatLeaseTtl, stuckReasonI18nKey } from './JobsDashboard.jsx'

describe('JobsDashboard lease diagnostics helpers', () => {
  it('isJobStuck is true only when the live API sent stuck_reason', () => {
    expect(isJobStuck({})).toBe(false)
    expect(isJobStuck({ status: 'running' })).toBe(false)
    expect(isJobStuck({ stuck_reason: 'heartbeat_stale' })).toBe(true)
    expect(isJobStuck({ stuck_reason: 'redis_lease_immortal' })).toBe(true)
  })

  it('formatLeaseTtl renders immortal, seconds, and missing', () => {
    expect(formatLeaseTtl({ lease: { immortal: true, ttl_secs: -1 } })).toBe('immortal')
    expect(formatLeaseTtl({ lease: { ttl_secs: 12 } })).toBe('12s')
    expect(formatLeaseTtl({ lease: { ttl_secs: 75 } })).toBe('1m 15s')
    expect(formatLeaseTtl({})).toBe('—')
    expect(formatLeaseTtl({ lease: { ttl_secs: -2 } })).toBe('—')
  })

  it('stuckReasonI18nKey maps API codes onto the jobs dashboard dictionary', () => {
    expect(stuckReasonI18nKey('redis_lease_immortal')).toBe(
      'pages.jobsDashboard.stuck_redis_lease_immortal',
    )
    expect(stuckReasonI18nKey(null)).toBe(null)
  })
})
