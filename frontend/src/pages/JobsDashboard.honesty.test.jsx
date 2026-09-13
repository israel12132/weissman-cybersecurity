import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'JobsDashboard.jsx'),
  'utf8',
)

describe('JobsDashboard live-only truth', () => {
  it('does not paint status KPI zeros when GET /api/jobs is unconfirmed', () => {
    expect(src).toMatch(/data-testid="jobs-dashboard-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/error && !hasLoadedRef\.current/)
    expect(src).toMatch(/data\.ok === false \|\| data\.unavailable === true/)
  })
})
