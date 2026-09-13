import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RemediationAnalytics.jsx'),
  'utf8',
)

describe('RemediationAnalytics live-only truth', () => {
  it('does not paint quiet heal totals when findings or heal-stats are unconfirmed', () => {
    expect(src).toMatch(/data-testid="remediation-analytics-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/results\.some\(\(x\) => x\.status === 'rejected'\)/)
    expect(src).toMatch(/setHealStats\(null\)/)
    expect(src).toMatch(/heals == null/)
    expect(src).not.toMatch(/\.catch\(\(\) => null\)/)
  })
})
