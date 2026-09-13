import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'RiskSuperpositionCollapse.jsx'),
  'utf8',
)

describe('RiskSuperpositionCollapse live-only truth', () => {
  it('does not paint no_clusters when GET /api/findings/clusters fails', () => {
    expect(src).toMatch(/data-testid="risk-superposition-clusters-unavailable"/)
    expect(src).toMatch(/clusters_unavailable/)
    expect(src).toMatch(/setClustersUnavailable\(true\)/)
    expect(src).toMatch(/clustersUnavailable \? '—'/)
    expect(src).toMatch(/data-testid="risk-superposition-clients-unavailable"/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint empty collapse findings when job-complete history fails', () => {
    expect(src).toMatch(/data-testid="risk-superposition-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/classifyEngineHistory/)
    expect(src).not.toMatch(/hist = \{\}/)
  })
})
