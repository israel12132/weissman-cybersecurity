import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RateLimitAnalytics.jsx'),
  'utf8',
)

describe('RateLimitAnalytics live-only truth', () => {
  it('does not paint leftover usage tiles when GET /api/rate-limits/analytics fails', () => {
    expect(src).toMatch(/data-testid="rate-limit-analytics-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/setError\(err\?\.message \|\| 'error'\)/)
    expect(src).not.toMatch(/setData\(null\)/)
    expect(src).toMatch(/error \? \(\s*<div data-testid="rate-limit-analytics-unavailable">/)
  })

  it('does not dump leftover leftover-analytics CSV after a failed analytics GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(error\) return/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
