import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'ServerlessSecurityCommandCenter.jsx'),
  'utf8',
)

describe('ServerlessSecurityCommandCenter live-only truth', () => {
  it('does not paint run-to-populate when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="serverless-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/unavailable=\{historyUnavailable\}/)
    expect(src).toMatch(/!historyUnavailable/)
  })

  it('does not paint leftover serverless posture when GET /api/engines/history fails', () => {
    expect(src).toMatch(/const liveMetrics = historyUnavailable \? null : metrics/)
    expect(src).toMatch(/\{liveMetrics && \(/)
    expect(src).toMatch(/!historyUnavailable && attackPaths\.length > 0/)
  })

  it('does not dump leftover leftover-findings CSV after a failed history GET', () => {
    expect(src).toMatch(/const handleExportCsv = useCallback\(\(\) => \{\n    if \(historyUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{historyUnavailable \|\| !filteredFindings\.length\}/)
  })

})
