import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'TargetScopePanel.jsx'),
  'utf8',
)

describe('TargetScopePanel live-only truth', () => {
  it('does not paint green no-zero-day when findings fetch fails', () => {
    expect(src).toMatch(/data-testid="target-scope-zeroday-unavailable"/)
    expect(src).toMatch(/findings_unavailable/)
    expect(src).toMatch(/setZeroDayUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => setZeroDayFindings\(\[\]\)\)/)
  })
})
