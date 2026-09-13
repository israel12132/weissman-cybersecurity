import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RiskGraphVisualization.jsx'),
  'utf8',
)

describe('RiskGraphVisualization live-only truth', () => {
  it('does not paint zero assets when the risk graph or attack-paths fetch is unconfirmed', () => {
    expect(src).toMatch(/data-testid="risk-graph-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/clientsUnavailable/)
    expect(src).toMatch(/setGraphUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => null\)/)
  })
})
