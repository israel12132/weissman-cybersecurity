import { describe, it, expect } from 'vitest'
import { computeSla, slaBand, SLA_TARGET_HOURS } from './incidentSla.js'

const HOUR = 3_600_000

describe('incidentSla', () => {
  it('uses severity-based targets', () => {
    expect(SLA_TARGET_HOURS.critical).toBe(1)
    expect(SLA_TARGET_HOURS.high).toBe(4)
    expect(SLA_TARGET_HOURS.low).toBe(72)
  })

  it('computes remaining time for an open incident', () => {
    const now = 10 * HOUR
    const sla = computeSla({ severity: 'medium', status: 'active', created: new Date(now - 2 * HOUR).toISOString() }, now)
    expect(sla.breached).toBe(false)
    expect(sla.remainingMs).toBe(22 * HOUR) // 24h target - 2h elapsed
    expect(slaBand(sla)).toBe('ok')
  })

  it('flags a breach when elapsed exceeds target', () => {
    const now = 10 * HOUR
    const sla = computeSla({ severity: 'critical', status: 'active', created: new Date(now - 3 * HOUR).toISOString() }, now)
    expect(sla.breached).toBe(true)
    expect(slaBand(sla)).toBe('breached')
  })

  it('enters warning band past 75% of target', () => {
    const now = 10 * HOUR
    // high target = 4h; 3.5h elapsed = 87.5%
    const sla = computeSla({ severity: 'high', status: 'active', created: new Date(now - 3.5 * HOUR).toISOString() }, now)
    expect(sla.breached).toBe(false)
    expect(slaBand(sla)).toBe('warning')
  })

  it('freezes the clock at resolution time for resolved incidents', () => {
    const created = 0
    const resolvedAt = 2 * HOUR
    const now = 100 * HOUR // long after resolution
    const sla = computeSla(
      { severity: 'critical', status: 'resolved', created: new Date(created).toISOString(), updated: new Date(resolvedAt).toISOString() },
      now,
    )
    // critical target 1h, resolved after 2h → breached but frozen
    expect(sla.resolved).toBe(true)
    expect(sla.breached).toBe(true)
    expect(slaBand(sla)).toBe('breached')
  })

  it('reports met SLA for an on-time resolution', () => {
    const sla = computeSla(
      { severity: 'high', status: 'resolved', created: new Date(0).toISOString(), updated: new Date(2 * HOUR).toISOString() },
      100 * HOUR,
    )
    expect(sla.breached).toBe(false)
    expect(slaBand(sla)).toBe('met')
  })

  it('handles a missing created timestamp gracefully', () => {
    const sla = computeSla({ severity: 'high', status: 'active' }, 10 * HOUR)
    expect(sla.unknown).toBe(true)
    expect(sla.breached).toBe(false)
  })

  it('freezes a resolved incident with no updated timestamp instead of drifting', () => {
    const created = new Date(0).toISOString()
    // Far-future clock: an unresolved incident would be massively breached; a
    // resolved one with no `updated` must freeze at created (elapsed 0 → met).
    const sla = computeSla({ severity: 'critical', status: 'resolved', created }, 5000 * HOUR)
    expect(sla.elapsedMs).toBe(0)
    expect(sla.breached).toBe(false)
    expect(slaBand(sla)).toBe('met')
  })
})
