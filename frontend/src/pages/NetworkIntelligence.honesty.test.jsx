import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'NetworkIntelligence.jsx'),
  'utf8',
)

describe('NetworkIntelligence live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="network-intelligence-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint appears-strong when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="network-intelligence-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce a missing hijack_resistance_score into a lime-0 gauge', () => {
    expect(src).toMatch(/summary\.hijack_resistance_score != null && Number\.isFinite\(Number\(summary\.hijack_resistance_score\)\)/)
    expect(src).toMatch(/<ScoreGauge score=\{score\} /)
    expect(src).not.toMatch(/<ScoreGauge score=\{score \?\? 0\}/)
    expect(src).not.toMatch(/Number\(summary\.hijack_resistance_score \?\? 0\)/)
  })
})
