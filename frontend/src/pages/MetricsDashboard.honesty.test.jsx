import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'MetricsDashboard.jsx'),
  'utf8',
)

describe('MetricsDashboard live-only truth', () => {
  it('does not seed live zeros while metrics are unconfirmed', () => {
    expect(src).not.toMatch(/useState\(EMPTY_METRICS\)/)
    expect(src).toMatch(/useState\(null\)/)
    expect(src).toMatch(/data-testid="metrics-dashboard-unavailable"/)
    expect(src).toMatch(/counters_unavailable_title/)
    expect(src).toMatch(/data\.unavailable/)
  })
})
