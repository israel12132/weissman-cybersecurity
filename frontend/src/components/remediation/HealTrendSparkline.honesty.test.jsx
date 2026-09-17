import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'HealTrendSparkline.jsx'),
  'utf8',
)

describe('HealTrendSparkline live-only truth', () => {
  it('does not hide a missing sparkline as zero heal activity', () => {
    expect(src).toMatch(/data-testid="heal-trend-unavailable"/)
    expect(src).toMatch(/pages\.healTrends\.unavailable/)
    expect(src).toMatch(/setUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => null\)/)
  })
})
