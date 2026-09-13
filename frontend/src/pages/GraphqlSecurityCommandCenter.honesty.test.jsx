import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'GraphqlSecurityCommandCenter.jsx'),
  'utf8',
)

describe('GraphqlSecurityCommandCenter live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="graphql-security-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).toMatch(/Array\.isArray\(d\?\.clients\)/)
    expect(src).not.toMatch(/\.then\(\(d\) => \{ if \(Array\.isArray\(d\)\) setClients\(d\) \}\)/)
  })

  it('does not paint ready-to-scan when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="graphql-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint a cyan-0 exposure ring when the score is unconfirmed', () => {
    expect(src).toMatch(/const hasScore = score != null && Number\.isFinite\(Number\(score\)\)/)
    expect(src).not.toMatch(/const pct = Math\.min\(100, Math\.max\(0, score \?\? 0\)\)/)
    expect(src).not.toMatch(/score \?\? 0/)
    expect(src).toMatch(/const liveMetrics = historyUnavailable \? null : metrics/)
    expect(src).toMatch(/<ExposureGauge score=\{liveMetrics\?\.exposure_score\} \/>/)
  })
})
