import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ComplianceFrameworks.jsx'),
  'utf8',
)

describe('ComplianceFrameworks live-only truth', () => {
  it('does not paint an unmapped tenant when GET /api/compliance/frameworks fails', () => {
    expect(src).toMatch(/data-testid="compliance-frameworks-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).not.toMatch(/setFrameworks\(\[\]\)/)
  })
})
