import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'PqcRadar.jsx'),
  'utf8',
)

describe('PqcRadar live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="pqc-radar-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/\.catch\(\(\) => \{\}\)/)
  })

  it('does not paint ready-to-scan when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="pqc-radar-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not coerce a missing readiness_score into a lime-0 gauge', () => {
    expect(src).toMatch(/summary\.readiness_score != null && Number\.isFinite\(Number\(summary\.readiness_score\)\)/)
    expect(src).toMatch(/<ScoreGauge score=\{score\} /)
    expect(src).not.toMatch(/<ScoreGauge score=\{score \?\? 0\}/)
    expect(src).not.toMatch(/Number\(summary\.readiness_score \?\? 0\)/)
    expect(src).toMatch(/summary && !historyUnavailable \?/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !sortedFindings\.length\}/)
  })

})
