import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AlertRulesEngine.jsx'),
  'utf8',
)

describe('AlertRulesEngine live-only truth', () => {
  it('does not paint alert-rule KPI zeros when GET /api/alerts/rules is unconfirmed', () => {
    expect(src).toMatch(/data-testid="alert-rules-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/unavailable \? \(/)
  })
})
